//! Linux cgroup v2 and tracked-process backend.

mod process;
mod real;
mod target;

pub use process::{ProcessHandle, ProcessIdentity};
pub use real::RealBackend;
pub use target::TargetStatus;

use scope_id::{ScopeId, TargetId};
use std::fmt;
use std::io;

/// A Linux process ID.
pub type Pid = u32;

/// Errors a [`CgroupBackend`] can report. These map onto D-Bus errors in
/// `crate::dbus`.
#[derive(Debug)]
pub enum BackendError {
    NotFound(ScopeId),
    AlreadyExists(ScopeId),
    PermissionDenied(ScopeId),
    ProcessNotFound(Pid),
    TargetAlreadyExists { scope: ScopeId, target: TargetId },
    ProcessAlreadyTracked { scope: ScopeId, target: TargetId },
    TargetNotFound { scope: ScopeId, target: TargetId },
    TargetGone { scope: ScopeId, target: TargetId },
    Io { context: String, source: io::Error },
}

impl BackendError {
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

    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        BackendError::Io {
            context: context.into(),
            source,
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
            BackendError::TargetAlreadyExists { scope, target } => {
                write!(
                    f,
                    "target {target} already names a live process in scope {scope}"
                )
            }
            BackendError::ProcessAlreadyTracked { scope, target } => write!(
                f,
                "process is already tracked as target {target} in scope {scope}"
            ),
            BackendError::TargetNotFound { scope, target } => {
                write!(f, "target {target} does not exist in scope {scope}")
            }
            BackendError::TargetGone { scope, target } => {
                write!(f, "target {target} is no longer alive in scope {scope}")
            }
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

/// Mechanism used by the policy/service layer. The Linux implementation is
/// [`RealBackend`]; tests use an in-memory fake.
pub trait CgroupBackend: Send + Sync + 'static {
    fn create(&self, id: &ScopeId) -> Result<(), BackendError>;

    /// Moves `pid` into `id`; when `target` is present, movement and durable
    /// registration are one client-visible operation.
    fn move_pid(
        &self,
        pid: Pid,
        id: &ScopeId,
        target: Option<&TargetId>,
    ) -> Result<(), BackendError>;

    fn scope_of(&self, pid: Pid) -> Result<Option<ScopeId>, BackendError>;
    fn list(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>, BackendError>;

    fn target_exists(&self, id: &ScopeId, target: &TargetId) -> Result<bool, BackendError>;
    fn terminate_target(&self, id: &ScopeId, target: &TargetId) -> Result<(), BackendError>;
    fn kill_target(&self, id: &ScopeId, target: &TargetId) -> Result<(), BackendError>;

    /// Freezes `id`, SIGTERMs every current member of it and its descendants
    /// through pidfds, then unconditionally thaws it. A missing scope is
    /// idempotent success.
    fn terminate_scope(&self, id: &ScopeId) -> Result<(), BackendError>;

    /// SIGKILLs every process in `id` and descendants via `cgroup.kill`.
    fn kill_scope(&self, id: &ScopeId) -> Result<(), BackendError>;

    /// A missing scope is defined as not populated, making teardown queries
    /// idempotent.
    fn is_populated(&self, id: &ScopeId) -> Result<bool, BackendError>;
}

impl<T: CgroupBackend + ?Sized> CgroupBackend for std::sync::Arc<T> {
    fn create(&self, id: &ScopeId) -> Result<(), BackendError> {
        (**self).create(id)
    }
    fn move_pid(
        &self,
        pid: Pid,
        id: &ScopeId,
        target: Option<&TargetId>,
    ) -> Result<(), BackendError> {
        (**self).move_pid(pid, id, target)
    }
    fn scope_of(&self, pid: Pid) -> Result<Option<ScopeId>, BackendError> {
        (**self).scope_of(pid)
    }
    fn list(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>, BackendError> {
        (**self).list(prefix)
    }
    fn target_exists(&self, id: &ScopeId, target: &TargetId) -> Result<bool, BackendError> {
        (**self).target_exists(id, target)
    }
    fn terminate_target(&self, id: &ScopeId, target: &TargetId) -> Result<(), BackendError> {
        (**self).terminate_target(id, target)
    }
    fn kill_target(&self, id: &ScopeId, target: &TargetId) -> Result<(), BackendError> {
        (**self).kill_target(id, target)
    }
    fn terminate_scope(&self, id: &ScopeId) -> Result<(), BackendError> {
        (**self).terminate_scope(id)
    }
    fn kill_scope(&self, id: &ScopeId) -> Result<(), BackendError> {
        (**self).kill_scope(id)
    }
    fn is_populated(&self, id: &ScopeId) -> Result<bool, BackendError> {
        (**self).is_populated(id)
    }
}
