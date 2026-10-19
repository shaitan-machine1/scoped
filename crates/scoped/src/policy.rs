//! The caller-uid-based policy from the plan: "root: anything. UID N: only
//! `user/<N>/...`, and only processes it owns."

use crate::procfs::{process_uid, ProcessLookupError};
use scope_id::ScopeId;

/// Why a policy check failed.
#[derive(Debug)]
pub enum PolicyError {
    /// The caller may not address this scope id at all.
    AccessDenied,
    /// The caller is not root and does not own the named process.
    NotProcessOwner,
    /// The named process does not exist (or just exited).
    ProcessNotFound(u32),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::AccessDenied => write!(f, "access denied"),
            PolicyError::NotProcessOwner => write!(f, "caller does not own this process"),
            PolicyError::ProcessNotFound(pid) => write!(f, "process {pid} does not exist"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Whether `caller_uid` may address `id` at all (root: anything; uid N:
/// only `user/<N>/...`).
pub fn check_address(caller_uid: u32, id: &ScopeId) -> Result<(), PolicyError> {
    if scope_id::policy::caller_may_address(caller_uid, id) {
        Ok(())
    } else {
        Err(PolicyError::AccessDenied)
    }
}

/// Whether `caller_uid` may act on `pid` directly (root: anything; uid N:
/// only processes it owns).
///
/// # Known weakness: pid reuse (TOCTOU)
///
/// This resolves a *number* to an owner, and the caller then acts on that
/// same number. If the process exits in between and the kernel recycles
/// its pid for an unrelated (possibly root-owned) process, the action
/// lands on the wrong process: an unprivileged caller could get a
/// root-owned process moved into a scope it controls, and then kill it.
/// The window is tiny and winning it requires driving pid wraparound, but
/// it is a real hole, not a theoretical one.
///
/// Closing it properly means pinning the process identity for the whole
/// operation -- hold an `O_PATH` fd on `/proc/<pid>` (or a pidfd), read
/// the uid and the current cgroup through *that*, act, then re-validate
/// through the same fd and undo if the identity changed. That is deferred:
/// see the README's "Known limitations".
pub fn check_owns_process(caller_uid: u32, pid: u32) -> Result<(), PolicyError> {
    if caller_uid == 0 {
        return Ok(());
    }
    match process_uid(pid) {
        Ok(uid) if uid == caller_uid => Ok(()),
        Ok(_) => Err(PolicyError::NotProcessOwner),
        Err(ProcessLookupError::NotFound) => Err(PolicyError::ProcessNotFound(pid)),
        Err(ProcessLookupError::Io(_)) => {
            // Can't verify ownership: fail closed.
            Err(PolicyError::AccessDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_may_address_anything() {
        let id = ScopeId::parse("sessiond/user/1000/service").unwrap();
        assert!(check_address(0, &id).is_ok());
    }

    #[test]
    fn user_restricted_to_own_namespace() {
        let own = ScopeId::parse("user/1000/sandbox").unwrap();
        let other = ScopeId::parse("user/2000/sandbox").unwrap();
        let sessiond = ScopeId::parse("sessiond/user/1000/service").unwrap();
        assert!(check_address(1000, &own).is_ok());
        assert!(check_address(1000, &other).is_err());
        assert!(check_address(1000, &sessiond).is_err());
    }

    #[test]
    fn root_owns_any_process() {
        assert!(check_owns_process(0, std::process::id()).is_ok());
    }

    #[test]
    fn caller_owns_its_own_process() {
        let my_uid = nix::unistd::Uid::current().as_raw();
        assert!(check_owns_process(my_uid, std::process::id()).is_ok());
    }

    #[test]
    fn caller_does_not_own_pid_1() {
        // pid 1 is virtually never owned by an unprivileged test runner.
        let my_uid = nix::unistd::Uid::current().as_raw();
        if my_uid != 0 {
            let err = check_owns_process(my_uid, 1).unwrap_err();
            assert!(matches!(
                err,
                PolicyError::NotProcessOwner | PolicyError::AccessDenied
            ));
        }
    }

    #[test]
    fn nonexistent_process_is_reported() {
        let my_uid = nix::unistd::Uid::current().as_raw();
        if my_uid != 0 {
            let err = check_owns_process(my_uid, 0x7fff_ffff).unwrap_err();
            assert!(matches!(err, PolicyError::ProcessNotFound(_)));
        }
    }
}
