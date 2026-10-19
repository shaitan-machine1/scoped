//! The cgroup v2 backend: the only part of `scoped` that touches cgroups.

mod real;

pub use real::RealBackend;

use scope_id::ScopeId;
use std::fmt;
use std::io;

/// A Linux process ID.
pub type Pid = u32;

/// A signal to send, as used by [`CgroupBackend::terminate`]. Re-exported
/// from `nix` rather than reinvented.
pub type Signal = nix::sys::signal::Signal;

/// Errors a [`CgroupBackend`] can report. These map fairly directly onto
/// D-Bus error names in `crate::dbus`.
#[derive(Debug)]
pub enum BackendError {
    /// The scope (or an ancestor needed to resolve it) does not exist.
    NotFound(ScopeId),
    /// `create` was called for a scope that already exists.
    AlreadyExists(ScopeId),
    /// The kernel refused an operation because of a permission problem.
    PermissionDenied(ScopeId),
    /// A pid named in a request does not exist (or just exited).
    ProcessNotFound(Pid),
    /// Any other I/O failure, tagged with what we were trying to do.
    Io { context: String, source: io::Error },
}

impl BackendError {
    /// Wraps an [`io::Error`] encountered while operating on `id`, during
    /// `op`, classifying well-known `errno`s into the more specific
    /// variants above.
    fn from_io(id: &ScopeId, op: &'static str, source: io::Error) -> Self {
        match source.kind() {
            io::ErrorKind::NotFound => BackendError::NotFound(id.clone()),
            io::ErrorKind::AlreadyExists => BackendError::AlreadyExists(id.clone()),
            io::ErrorKind::PermissionDenied => BackendError::PermissionDenied(id.clone()),
            _ => BackendError::Io {
                context: format!("{op} on scope {id}"),
                source,
            },
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::NotFound(id) => write!(f, "scope {id} does not exist"),
            BackendError::AlreadyExists(id) => write!(f, "scope {id} already exists"),
            BackendError::PermissionDenied(id) => {
                write!(f, "permission denied operating on scope {id}")
            }
            BackendError::ProcessNotFound(pid) => write!(f, "process {pid} does not exist"),
            BackendError::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for BackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BackendError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Everything `scoped` needs from cgroup v2 to implement `Create`, `Move`,
/// `ScopeOf`, `List`, `Terminate` and `Kill`. Scope IDs here are always
/// relative to the root this backend manages (see `RealBackend::new`).
///
/// This trait exists so `Service` (see `crate::service`) can be unit
/// tested; in practice `RealBackend` is the only implementation, since a
/// faithful fake would have to reimplement kernel cgroup semantics
/// (`cgroup.events`, `cgroup.kill`, EBUSY-on-populated-rmdir, ...) to be
/// useful for anything beyond pure directory-structure tests.
pub trait CgroupBackend: Send + Sync + 'static {
    /// Creates `id`, creating any missing ancestor directories first.
    /// Fails with `AlreadyExists` if `id` itself already exists.
    fn create(&self, id: &ScopeId) -> Result<(), BackendError>;

    /// True if `id` currently exists.
    ///
    /// Not called from `scoped`'s own request handling today (`create`'s
    /// `mkdir` already reports `AlreadyExists` on its own), but part of
    /// the backend's documented contract; exercised by tests and useful
    /// for diagnostics/future callers.
    #[allow(dead_code)]
    fn exists(&self, id: &ScopeId) -> Result<bool, BackendError>;

    /// Moves `pid` into `id`'s `cgroup.procs`.
    fn move_pid(&self, pid: Pid, id: &ScopeId) -> Result<(), BackendError>;

    /// The scope `pid` currently belongs to, or `None` if `pid` is not
    /// inside any scope this backend manages (or does not exist).
    fn scope_of(&self, pid: Pid) -> Result<Option<ScopeId>, BackendError>;

    /// All descendant scope IDs under `prefix` (not including `prefix`
    /// itself), at any depth.
    fn list(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>, BackendError>;

    /// The pids directly listed in `id`'s own `cgroup.procs` (not
    /// descendants' scopes).
    fn members(&self, id: &ScopeId) -> Result<Vec<Pid>, BackendError>;

    /// Sends `signal` to every process in `id` and all its descendant
    /// scopes. Best-effort and racy by nature (a process can exit, or a new
    /// one can join, between listing members and signalling them); does
    /// not wait for anything to die.
    fn terminate(&self, id: &ScopeId, signal: Signal) -> Result<(), BackendError>;

    /// Atomically SIGKILLs every process in `id` and all its descendants,
    /// via `cgroup.kill`.
    fn kill(&self, id: &ScopeId) -> Result<(), BackendError>;

    /// Reads `id`'s `cgroup.events` `populated` field: whether `id` or any
    /// descendant currently has a member process.
    ///
    /// `crate::watch` reads `cgroup.events` itself (it needs the raw file
    /// for `poll()`, not just the parsed value), so this trait method is
    /// currently only exercised by tests; kept for completeness and for
    /// any future caller that just wants a one-shot answer.
    #[allow(dead_code)]
    fn is_populated(&self, id: &ScopeId) -> Result<bool, BackendError>;
}

/// Lets `Service` and `main` share one backend instance (an `Arc<RealBackend>`,
/// also used directly by `crate::watch`) without `Service` having to know
/// about `Arc` itself.
impl<T: CgroupBackend + ?Sized> CgroupBackend for std::sync::Arc<T> {
    fn create(&self, id: &ScopeId) -> Result<(), BackendError> {
        (**self).create(id)
    }
    fn exists(&self, id: &ScopeId) -> Result<bool, BackendError> {
        (**self).exists(id)
    }
    fn move_pid(&self, pid: Pid, id: &ScopeId) -> Result<(), BackendError> {
        (**self).move_pid(pid, id)
    }
    fn scope_of(&self, pid: Pid) -> Result<Option<ScopeId>, BackendError> {
        (**self).scope_of(pid)
    }
    fn list(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>, BackendError> {
        (**self).list(prefix)
    }
    fn members(&self, id: &ScopeId) -> Result<Vec<Pid>, BackendError> {
        (**self).members(id)
    }
    fn terminate(&self, id: &ScopeId, signal: Signal) -> Result<(), BackendError> {
        (**self).terminate(id, signal)
    }
    fn kill(&self, id: &ScopeId) -> Result<(), BackendError> {
        (**self).kill(id)
    }
    fn is_populated(&self, id: &ScopeId) -> Result<bool, BackendError> {
        (**self).is_populated(id)
    }
}
