//! Process ownership lookups, used by [`crate::service::Service`] to
//! enforce "a non-root caller may only move processes it owns".

use std::io;
use std::os::unix::fs::MetadataExt;

/// Error looking up a process's owning uid.
#[derive(Debug)]
pub enum ProcessLookupError {
    /// The process does not exist (or just exited).
    NotFound,
    /// Some other I/O failure.
    Io(io::Error),
}

impl std::fmt::Display for ProcessLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessLookupError::NotFound => write!(f, "process does not exist"),
            ProcessLookupError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProcessLookupError {}

/// The uid that owns `pid`, found the same way `polkit` and `systemd` do:
/// the owner of `/proc/<pid>` is the process's (real) uid.
pub fn process_uid(pid: u32) -> Result<u32, ProcessLookupError> {
    match std::fs::metadata(format!("/proc/{pid}")) {
        Ok(meta) => Ok(meta.uid()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(ProcessLookupError::NotFound),
        Err(e) => Err(ProcessLookupError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process_is_owned_by_own_uid() {
        let pid = std::process::id();
        let uid = process_uid(pid).expect("our own /proc entry must exist");
        assert_eq!(uid, nix::unistd::Uid::current().as_raw());
    }

    #[test]
    fn nonexistent_process_is_not_found() {
        // pid 1 always exists on Linux; use a pid unlikely to ever exist as
        // an actual process (max pid is usually far below this).
        let err = process_uid(0x7fff_ffff).unwrap_err();
        assert!(matches!(err, ProcessLookupError::NotFound));
    }
}
