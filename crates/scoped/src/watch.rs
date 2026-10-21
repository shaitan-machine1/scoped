//! Background empty-scope watching and garbage collection.
//!
//! Durable state lives in the cgroup tree: scope directories plus target
//! xattrs. This module only caches watcher bookkeeping and pidfds; startup
//! reconstructs both scope and target watchers from that tree.

use crate::backend::{BackendError, ProcessIdentity, RealBackend, TargetStatus};
use crate::dbus::Manager;
use scope_id::{ScopeId, TargetId};
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
    // Scope stops are not wired to daemon shutdown yet. Target stops are
    // used immediately when the same `(scope, target)` binding is replaced.
    scope_handles: Mutex<HashMap<ScopeId, Arc<AtomicBool>>>,
    target_handles: Mutex<HashMap<(ScopeId, TargetId), Arc<AtomicBool>>>,
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
            scope_handles: Mutex::new(HashMap::new()),
            target_handles: Mutex::new(HashMap::new()),
        }))
    }

    /// Starts watching a scope id that was just created by `Create()`.
    /// Must be called right after a successful `backend.create(id)`.
    pub fn watch_new(&self, id: ScopeId) {
        self.spawn(id, false);
    }

    /// Starts (or replaces) the pidfd watcher for a tracked target. Replacing
    /// the map entry before stopping the old thread gives every binding a
    /// generation: a delayed watcher can never remove or emit for a newer
    /// process that reused the same target ID.
    pub fn watch_target(&self, id: ScopeId, target: TargetId) {
        let stop = Arc::new(AtomicBool::new(false));
        let key = (id.clone(), target.clone());
        if let Some(old) = self
            .0
            .target_handles
            .lock()
            .unwrap()
            .insert(key, stop.clone())
        {
            old.store(true, Ordering::Relaxed);
        }
        let this = self.clone();
        let thread_name = format!("scoped-target-{id}-{target}");
        let thread_id = id.clone();
        let thread_target = target.clone();
        let thread_stop = stop.clone();
        let built = thread::Builder::new().name(thread_name).spawn(move || {
            this.run_target(thread_id, thread_target, thread_stop);
        });
        if let Err(e) = built {
            tracing::error!(%id, %target, error = %e, "failed to spawn target watcher thread");
            self.forget_target_if_current(&id, &target, &stop);
        }
    }

    fn spawn(&self, id: ScopeId, seen_populated: bool) {
        let stop = Arc::new(AtomicBool::new(false));
        {
            let mut handles = self.0.scope_handles.lock().unwrap();
            if handles.contains_key(&id) {
                return; // already watched (startup scan racing a Create, belt and suspenders)
            }
            handles.insert(id.clone(), stop.clone());
        }
        let this = self.clone();
        let thread_name = format!("scoped-watch-{id}");
        let thread_id = id.clone();
        let thread_stop = stop.clone();
        let built = thread::Builder::new().name(thread_name).spawn(move || {
            this.run(thread_id, seen_populated, thread_stop);
        });
        if let Err(e) = built {
            tracing::error!(%id, error = %e, "failed to spawn scope watcher thread");
            self.forget(&id);
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
            let mut file = match File::open(&events_path) {
                Ok(f) => f,
                Err(_) => {
                    // Directory (or just the events file) is gone already.
                    self.forget(&id);
                    return;
                }
            };
            // Reading the exact fd that is about to be polled synchronizes
            // kernfs's per-open event counter. Reading through a second open
            // leaves this fd immediately ready with POLLPRI|POLLERR and turns
            // the watcher into a busy loop.
            let populated = match RealBackend::read_populated_file(&mut file, &path) {
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
        self.0.scope_handles.lock().unwrap().remove(id);
    }

    fn run_target(&self, id: ScopeId, target: TargetId, stop: Arc<AtomicBool>) {
        let handle = match self.0.backend.target_status(&id, &target) {
            Ok(TargetStatus::Live(handle)) => handle,
            Ok(TargetStatus::Gone) => {
                let _ = self.0.backend.remove_stale_target(&id, &target);
                self.finish_target(&id, &target, &stop, None);
                return;
            }
            Ok(TargetStatus::Missing) | Err(BackendError::NotFound(_)) => {
                self.finish_target(&id, &target, &stop, None);
                return;
            }
            Err(e) => {
                tracing::warn!(%id, %target, error = %e, "failed to open tracked target");
                self.forget_target_if_current(&id, &target, &stop);
                return;
            }
        };
        let identity = handle.identity();
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let mut fds = [PollFd::new(handle.as_fd(), PollFlags::POLLIN)];
            let timeout = PollTimeout::try_from(POLL_INTERVAL).unwrap_or(PollTimeout::MAX);
            let ready = poll(&mut fds, timeout).unwrap_or(0);
            if stop.load(Ordering::Relaxed) {
                return;
            }
            if ready > 0 {
                self.finish_target(&id, &target, &stop, Some(identity));
                return;
            }
            // The pidfd only reports process exit. A target can also become
            // invalid because scoped moved it to another scope, so verify the
            // durable binding on the same safety-net interval.
            match self.0.backend.target_status(&id, &target) {
                Ok(TargetStatus::Live(current)) if current.identity() == identity => {}
                Ok(_) | Err(BackendError::NotFound(_)) => {
                    self.finish_target(&id, &target, &stop, Some(identity));
                    return;
                }
                Err(e) => {
                    tracing::warn!(%id, %target, error = %e, "failed to revalidate tracked target");
                }
            }
        }
    }

    fn forget_target_if_current(
        &self,
        id: &ScopeId,
        target: &TargetId,
        stop: &Arc<AtomicBool>,
    ) -> bool {
        let key = (id.clone(), target.clone());
        let mut handles = self.0.target_handles.lock().unwrap();
        if handles
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, stop))
        {
            handles.remove(&key);
            true
        } else {
            false
        }
    }

    fn finish_target(
        &self,
        id: &ScopeId,
        target: &TargetId,
        stop: &Arc<AtomicBool>,
        identity: Option<ProcessIdentity>,
    ) {
        if !self.forget_target_if_current(id, target, stop) {
            return;
        }
        if let Some(identity) = identity {
            if let Err(e) = self.0.backend.remove_target_if(id, target, identity) {
                // The cgroup may already have been reclaimed; TargetGone is
                // still the correct event for the watcher generation.
                tracing::debug!(%id, %target, error = %e, "target record was already unavailable");
            }
        }
        self.emit_target_gone_blocking(id, target);
    }

    fn handle_empty(&self, id: &ScopeId, path: &Path) {
        self.emit_empty_blocking(id);
        if std::fs::remove_dir(path).is_err() {
            // Raced with a fresh Move() landing just as we observed
            // "populated 0" (or someone else removed it already). Either
            // way, there is nothing more to do here; a later transition
            // (if any) will be handled by a fresh watcher from the next
            // Create(), or this is simply gone.
            return;
        }
        self.emit_removed_blocking(id);
        self.cascade(id);
    }

    /// After removing `id`, tries to remove now-possibly-empty ancestor
    /// directories, stopping at the first one that still has children (or
    /// at the managed root, which `ScopeId::ancestors` never reaches).
    fn cascade(&self, id: &ScopeId) {
        for ancestor in id.ancestors() {
            let path = self.0.backend.fs_path(&ancestor);
            match std::fs::remove_dir(&path) {
                Ok(()) => self.emit_removed_blocking(&ancestor),
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

    async fn emit_target_gone(&self, id: &ScopeId, target: &TargetId) {
        let Some(emitter) = self.emitter(id) else {
            return;
        };
        let id_str = id.to_string();
        let target_str = target.to_string();
        if let Err(e) = Manager::target_gone(&emitter, &id_str, &target_str).await {
            tracing::warn!(%id, %target, error = %e, "failed to emit TargetGone");
        }
    }

    async fn emit_empty(&self, id: &ScopeId) {
        let Some(emitter) = self.emitter(id) else {
            return;
        };
        let id_str = id.to_string();
        if let Err(e) = Manager::scope_empty(&emitter, &id_str).await {
            tracing::warn!(%id, error = %e, "failed to emit ScopeEmpty");
        }
    }

    async fn emit_removed(&self, id: &ScopeId) {
        let Some(emitter) = self.emitter(id) else {
            return;
        };
        let id_str = id.to_string();
        if let Err(e) = Manager::scope_removed(&emitter, &id_str).await {
            tracing::warn!(%id, error = %e, "failed to emit ScopeRemoved");
        }
    }

    // The `_blocking` wrappers below are for the watcher threads, which are
    // plain OS threads of our own and so may block on the bus runtime.
    // Anything already running *inside* that runtime (notably
    // `startup_scan`, which runs as part of `main`'s top-level future) must
    // use the `async` forms instead: `zbus::block_on` panics outright when
    // called from a task the runtime is driving.

    fn emit_target_gone_blocking(&self, id: &ScopeId, target: &TargetId) {
        zbus::block_on(self.emit_target_gone(id, target));
    }

    fn emit_empty_blocking(&self, id: &ScopeId) {
        zbus::block_on(self.emit_empty(id));
    }

    fn emit_removed_blocking(&self, id: &ScopeId) {
        zbus::block_on(self.emit_removed(id));
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
    pub async fn startup_scan(&self) {
        let base = self.0.backend.base();
        // The sweep itself is synchronous and must not touch the bus: it
        // runs as part of the daemon's top-level future, where
        // `zbus::block_on` would panic. So it just records what it removed
        // and the signals go out here, afterwards.
        let mut removed = Vec::new();
        self.scan_dir(&base, &mut removed);
        for id in &removed {
            self.emit_removed(id).await;
        }
    }

    /// Returns `true` if `dir` ends up with no children and no members
    /// after this call (i.e. the caller should remove it itself).
    /// Appends every scope it removes to `removed`.
    fn scan_dir(&self, dir: &Path, removed: &mut Vec<ScopeId>) -> bool {
        let base = self.0.backend.base();
        let is_root = dir == base.as_path();
        if !is_root {
            if let Some(id) = self.0.backend.id_for_path(dir) {
                match self.0.backend.target_ids(&id) {
                    Ok(targets) => {
                        for target in targets {
                            self.watch_target(id.clone(), target);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%id, error = %e, "failed to recover tracked targets");
                    }
                }
            }
        }
        let children = RealBackend::subdirs(dir).unwrap_or_default();
        let mut all_children_gone = true;
        for name in &children {
            let child = dir.join(name);
            if self.scan_dir(&child, removed) {
                if std::fs::remove_dir(&child).is_ok() {
                    if let Some(id) = self.0.backend.id_for_path(&child) {
                        removed.push(id);
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
