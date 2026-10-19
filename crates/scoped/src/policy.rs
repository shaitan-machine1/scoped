//! Phase 1 authorization: every scoped operation is root-only.
//!
//! The system-bus policy rejects unprivileged traffic too, but this check is
//! the actual authorization boundary and therefore applies to every method.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    AccessDenied,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "scoped is root-only")
    }
}

impl std::error::Error for PolicyError {}

pub fn check_root(caller_uid: u32) -> Result<(), PolicyError> {
    if caller_uid == 0 {
        Ok(())
    } else {
        Err(PolicyError::AccessDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_allowed() {
        assert_eq!(check_root(0), Ok(()));
    }

    #[test]
    fn every_non_root_uid_is_denied() {
        for uid in [1, 1000, 65534, u32::MAX] {
            assert_eq!(check_root(uid), Err(PolicyError::AccessDenied));
        }
    }
}
