//! Background empty-scope watching and garbage collection.
//!
//! "State lives entirely in the cgroup tree" (per the plan) means `scoped`
//! keeps nothing durable in memory. The one thing it *does* keep in memory
//! is this module's bookkeeping -- which scopes have a watcher thread, and
//! whether each has ever been populated -- and that's fine, because
//! [`Watchers::startup_scan`] can always rebuild it from the tree alone.

use crate::backend::RealBackend;
use crate::dbus::Manager;
use scope_id::ScopeId;
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use zbus::object_server::SignalEmitter;
use zbus::{Connection, OwnedObjectPath};

/// How often a watcher thread re-checks `cgroup.events` even without a
/// `POLLPRI` wakeup. Pure safety net; real transitions are observed
/// through `poll()` directly.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Spawns and tracks the background threads that watch `Create()`-d scopes
/// for becoming empty, remove them (and any now-empty ancestor
/// directories) when they do, and emit `ScopeEmpty`/`ScopeRemoved` on the
/// bus.
///
/// Design note: one OS thread per watched (leaf) scope, each blocked in
/// `poll()` on that scope's `cgroup.events` fd with `POLLPRI`. Intermediate
/// (non-leaf) directories never get a dedicated watcher: they never have
/// members of their own, so their emptiness is entirely a function of
/// their descendants, and is handled by the upward cascade after a leaf is
/// removed (see [`Watchers::cascade`]). Simple and correct; a shared epoll
/// loop would use fewer threads but isn't needed at the scope counts a
/// login manager deals with.
///
/// Only a genuine populated 1 -> 0 *transition* triggers removal. A scope
/// that has never been populated is never auto-removed by its watcher,
/// which is what makes `Create()` immediately followed by `Move()` safe:
/// otherwise the watcher could remove a brand new, still-empty scope
/// before the caller gets to move a process into it.
#[derive(Clone)]
pub struct Watchers(Arc<Inner>);

struct Inner {
    backend: Arc<RealBackend>,
    connection: Connection,
    object_path: OwnedObjectPath,
    // The `AtomicBool` lets a watcher thread be asked to stop; nothing
    // sets it yet (no graceful-shutdown path exists until SIGTERM handling
    // lands, see the TODO in main.rs), so it's effectively always `false`
    // today, but `run` already honors it correctly.
    handles: Mutex<HashMap<ScopeId, Arc<AtomicBool>>>,
}

impl Watchers {
    pub fn new(
        backend: Arc<RealBackend>,
        connection: Connection,
        object_path: OwnedObjectPath,
    ) -> Self {
        Watchers(Arc::new(Inner {
            backend,
            connection,
            object_path,
            handles: Mutex::new(HashMap::new()),
        }))
    }

    /// Starts watching a scope id that was just created by `Create()`.
    /// Must be called right after a successful `backend.create(id)`.
    pub fn watch_new(&self, id: ScopeId) {
        self.spawn(id, false);
    }

    fn spawn(&self, id: ScopeId, seen_populated: bool) {
        let stop = Arc::new(AtomicBool::new(false));
        {
            let mut handles = self.0.handles.lock().unwrap();
            if handles.contains_key(&id) {
                return; // already watched (startup scan racing a Create, belt and suspenders)
            }
            handles.insert(id.clone(), stop.clone());
        }
        let this = self.clone();
        let thread_name = format!("scoped-watch-{id}");
        let built = thread::Builder::new().name(thread_name).spawn(move || {
            this.run(id, seen_populated, stop);
        });
        if let Err(e) = built {
            tracing::error!(error = %e, "failed to spawn scope watcher thread");
        }
    }

    fn run(&self, id: ScopeId, mut seen_populated: bool, stop: Arc<AtomicBool>) {
        let path = self.0.backend.fs_path(&id);
        loop {
            if stop.load(Ordering::Relaxed) {
                self.forget(&id);
                return;
            }
            let events_path = path.join("cgroup.events");
            let file = match File::open(&events_path) {
                Ok(f) => f,
                Err(_) => {
                    // Directory (or just the events file) is gone already.
                    self.forget(&id);
                    return;
                }
            };
            let populated = match RealBackend::read_populated(&path) {
                Ok(p) => p,
                Err(_) => {
                    self.forget(&id);
                    return;
                }
            };
            if populated {
                seen_populated = true;
            } else if seen_populated {
                self.handle_empty(&id, &path);
                self.forget(&id);
                return;
            }
            let mut fds = [PollFd::new(file.as_fd(), PollFlags::POLLPRI)];
            let timeout = PollTimeout::try_from(POLL_INTERVAL).unwrap_or(PollTimeout::MAX);
            // Errors and timeouts are both just "go around and re-read":
            // the only thing that matters is the fresh read above.
            let _ = poll(&mut fds, timeout);
        }
    }

    fn forget(&self, id: &ScopeId) {
        self.0.handles.lock().unwrap().remove(id);
    }

    fn handle_empty(&self, id: &ScopeId, path: &Path) {
        self.emit_empty(id);
        if std::fs::remove_dir(path).is_err() {
            // Raced with a fresh Move() landing just as we observed
            // "populated 0" (or someone else removed it already). Either
            // way, there is nothing more to do here; a later transition
            // (if any) will be handled by a fresh watcher from the next
            // Create(), or this is simply gone.
            return;
        }
        self.emit_removed(id);
        self.cascade(id);
    }

    /// After removing `id`, tries to remove now-possibly-empty ancestor
    /// directories, stopping at the first one that still has children (or
    /// at the managed root, which `ScopeId::ancestors` never reaches).
    fn cascade(&self, id: &ScopeId) {
        for ancestor in id.ancestors() {
            let path = self.0.backend.fs_path(&ancestor);
            match std::fs::remove_dir(&path) {
                Ok(()) => self.emit_removed(&ancestor),
                Err(_) => break,
            }
        }
    }

    fn emitter(&self, id: &ScopeId) -> Option<SignalEmitter<'static>> {
        match SignalEmitter::new(&self.0.connection, self.0.object_path.clone()) {
            Ok(e) => Some(e),
            Err(e) => {
                tracing::warn!(%id, error = %e, "failed to build signal emitter");
                None
            }
        }
    }

    fn emit_empty(&self, id: &ScopeId) {
        let Some(emitter) = self.emitter(id) else {
            return;
        };
        let id_str = id.to_string();
        if let Err(e) = zbus::block_on(Manager::scope_empty(&emitter, &id_str)) {
            tracing::warn!(%id, error = %e, "failed to emit ScopeEmpty");
        }
    }

    fn emit_removed(&self, id: &ScopeId) {
        let Some(emitter) = self.emitter(id) else {
            return;
        };
        let id_str = id.to_string();
        if let Err(e) = zbus::block_on(Manager::scope_removed(&emitter, &id_str)) {
            tracing::warn!(%id, error = %e, "failed to emit ScopeRemoved");
        }
    }

    /// Walks the whole managed tree once, bottom-up: removes any leaf
    /// directory (no children) that is currently unpopulated -- cascading
    /// into ancestors that become empty as a result -- and starts a
    /// watcher (with `seen_populated = true`) for every leaf that remains
    /// populated. Must run to completion before the daemon starts serving
    /// D-Bus requests, so no `Create()` can race it.
    ///
    /// A scope created immediately before a crash, with its `Move()` not
    /// yet landed, looks identical on disk to stale leftover garbage: both
    /// are an empty leaf directory. This sweep removes both; the caller
    /// that was about to `Move()` into it gets a `NotFound` error instead
    /// of succeeding. See the plan's "Accepted limitations".
    pub fn startup_scan(&self) {
        let base = self.0.backend.base();
        self.scan_dir(&base);
    }

    /// Returns `true` if `dir` ends up with no children and no members
    /// after this call (i.e. the caller should remove it itself).
    fn scan_dir(&self, dir: &Path) -> bool {
        let base = self.0.backend.base();
        let is_root = dir == base.as_path();
        let children = RealBackend::subdirs(dir).unwrap_or_default();
        let mut all_children_gone = true;
        for name in &children {
            let child = dir.join(name);
            if self.scan_dir(&child) {
                if std::fs::remove_dir(&child).is_ok() {
                    if let Some(id) = self.0.backend.id_for_path(&child) {
                        self.emit_removed(&id);
                    }
                } else {
                    all_children_gone = false;
                }
            } else {
                all_children_gone = false;
            }
        }
        if !all_children_gone || is_root {
            return false;
        }
        let populated = RealBackend::read_populated(dir).unwrap_or(false);
        if populated {
            if let Some(id) = self.0.backend.id_for_path(dir) {
                self.spawn(id, true);
            }
            false
        } else {
            true
        }
    }
}
