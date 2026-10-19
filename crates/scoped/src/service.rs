//! The core "Create/Move/ScopeOf/List/Terminate/Kill" logic, independent of
//! D-Bus: a thin, policy-enforcing wrapper around a [`CgroupBackend`].
//! Kept separate from `crate::dbus` so it can be unit tested without a bus.

use crate::backend::{BackendError, CgroupBackend, Pid, Signal};
use crate::policy::{self, PolicyError};
use scope_id::ScopeId;
use std::fmt;

/// Errors `Service` methods can return.
#[derive(Debug)]
pub enum ServiceError {
    Policy(PolicyError),
    Backend(BackendError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::Policy(e) => write!(f, "{e}"),
            ServiceError::Backend(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServiceError::Policy(e) => Some(e),
            ServiceError::Backend(e) => Some(e),
        }
    }
}

impl From<PolicyError> for ServiceError {
    fn from(e: PolicyError) -> Self {
        ServiceError::Policy(e)
    }
}

impl From<BackendError> for ServiceError {
    fn from(e: BackendError) -> Self {
        ServiceError::Backend(e)
    }
}

/// The scope manager's core logic, generic over the backend so tests can
/// swap in a fake for the parts that don't need real cgroup semantics.
pub struct Service<B: CgroupBackend> {
    backend: B,
}

impl<B: CgroupBackend> Service<B> {
    pub fn new(backend: B) -> Self {
        Service { backend }
    }

    /// Direct backend access, for diagnostics and tests.
    #[allow(dead_code)]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// `Create(id)`: atomic, fails if `id` already exists.
    pub fn create(&self, caller_uid: u32, id: &ScopeId) -> Result<(), ServiceError> {
        policy::check_address(caller_uid, id)?;
        self.backend.create(id)?;
        Ok(())
    }

    /// `Move(pid, id)`: moves a process into a scope. A non-root caller may
    /// only move processes it owns.
    pub fn move_pid(&self, caller_uid: u32, pid: Pid, id: &ScopeId) -> Result<(), ServiceError> {
        policy::check_address(caller_uid, id)?;
        policy::check_owns_process(caller_uid, pid)?;
        self.backend.move_pid(pid, id)?;
        Ok(())
    }

    /// `ScopeOf(pid) -> id`. A non-root caller may only query processes it
    /// owns.
    pub fn scope_of(&self, caller_uid: u32, pid: Pid) -> Result<Option<ScopeId>, ServiceError> {
        policy::check_owns_process(caller_uid, pid)?;
        Ok(self.backend.scope_of(pid)?)
    }

    /// `List(prefix) -> ids`.
    pub fn list(&self, caller_uid: u32, prefix: &ScopeId) -> Result<Vec<ScopeId>, ServiceError> {
        policy::check_address(caller_uid, prefix)?;
        Ok(self.backend.list(prefix)?)
    }

    /// `Terminate(id, signal)`: signals all members; does not wait.
    pub fn terminate(
        &self,
        caller_uid: u32,
        id: &ScopeId,
        signal: Signal,
    ) -> Result<(), ServiceError> {
        policy::check_address(caller_uid, id)?;
        self.backend.terminate(id, signal)?;
        Ok(())
    }

    /// `Kill(id)`: SIGKILLs all members via `cgroup.kill`.
    pub fn kill(&self, caller_uid: u32, id: &ScopeId) -> Result<(), ServiceError> {
        policy::check_address(caller_uid, id)?;
        self.backend.kill(id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Mutex;

    /// A fake backend over a plain in-memory tree, for policy/plumbing
    /// tests that don't need real cgroup semantics (membership, kill,
    /// populated events). See `crate::backend::real` tests and
    /// `tests/e2e.rs` for those.
    #[derive(Default)]
    struct FakeBackend {
        scopes: Mutex<BTreeSet<ScopeId>>,
        members: Mutex<HashMap<ScopeId, Vec<Pid>>>,
        pid_scope: Mutex<HashMap<Pid, ScopeId>>,
    }

    impl CgroupBackend for FakeBackend {
        fn create(&self, id: &ScopeId) -> Result<(), BackendError> {
            if !self.scopes.lock().unwrap().insert(id.clone()) {
                return Err(BackendError::AlreadyExists(id.clone()));
            }
            Ok(())
        }
        fn exists(&self, id: &ScopeId) -> Result<bool, BackendError> {
            Ok(self.scopes.lock().unwrap().contains(id))
        }
        fn move_pid(&self, pid: Pid, id: &ScopeId) -> Result<(), BackendError> {
            if !self.scopes.lock().unwrap().contains(id) {
                return Err(BackendError::NotFound(id.clone()));
            }
            self.pid_scope.lock().unwrap().insert(pid, id.clone());
            self.members
                .lock()
                .unwrap()
                .entry(id.clone())
                .or_default()
                .push(pid);
            Ok(())
        }
        fn scope_of(&self, pid: Pid) -> Result<Option<ScopeId>, BackendError> {
            Ok(self.pid_scope.lock().unwrap().get(&pid).cloned())
        }
        fn list(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>, BackendError> {
            Ok(self
                .scopes
                .lock()
                .unwrap()
                .iter()
                .filter(|id| *id != prefix && id.is_or_is_under(prefix))
                .cloned()
                .collect())
        }
        fn members(&self, id: &ScopeId) -> Result<Vec<Pid>, BackendError> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .unwrap_or_default())
        }
        fn terminate(&self, _id: &ScopeId, _signal: Signal) -> Result<(), BackendError> {
            Ok(())
        }
        fn kill(&self, _id: &ScopeId) -> Result<(), BackendError> {
            Ok(())
        }
        fn is_populated(&self, id: &ScopeId) -> Result<bool, BackendError> {
            Ok(!self.members(id)?.is_empty())
        }
    }

    #[test]
    fn root_can_create_sessiond_scope() {
        let svc = Service::new(FakeBackend::default());
        let id = ScopeId::parse("sessiond/user/1000/service").unwrap();
        assert!(svc.create(0, &id).is_ok());
        assert!(svc.create(0, &id).is_err()); // already exists
        assert!(svc.backend().exists(&id).unwrap());
    }

    #[test]
    fn non_root_cannot_create_sessiond_scope() {
        let svc = Service::new(FakeBackend::default());
        let id = ScopeId::parse("sessiond/user/1000/service").unwrap();
        assert!(matches!(
            svc.create(1000, &id),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
    }

    #[test]
    fn non_root_can_create_own_user_scope() {
        let svc = Service::new(FakeBackend::default());
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        assert!(svc.create(1000, &id).is_ok());
    }

    #[test]
    fn non_root_cannot_create_other_user_scope() {
        let svc = Service::new(FakeBackend::default());
        let id = ScopeId::parse("user/2000/sandbox").unwrap();
        assert!(matches!(
            svc.create(1000, &id),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
    }

    #[test]
    fn move_requires_owning_the_process() {
        let svc = Service::new(FakeBackend::default());
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        svc.create(1000, &id).unwrap();

        let my_pid = std::process::id();
        let my_uid = nix::unistd::Uid::current().as_raw();
        if my_uid != 0 {
            // Caller (uid 1000, hypothetically) does not own the test
            // runner's own pid unless the runner really is uid 1000.
            if my_uid != 1000 {
                assert!(svc.move_pid(1000, my_pid, &id).is_err());
            }
        }
    }

    #[test]
    fn root_can_move_any_process_anywhere_it_may_address() {
        let svc = Service::new(FakeBackend::default());
        let id = ScopeId::parse("sessiond/user/1000/service").unwrap();
        svc.create(0, &id).unwrap();
        assert!(svc.move_pid(0, std::process::id(), &id).is_ok());
        assert_eq!(svc.scope_of(0, std::process::id()).unwrap(), Some(id));
    }

    #[test]
    fn list_excludes_prefix_itself() {
        let svc = Service::new(FakeBackend::default());
        let root = ScopeId::parse("sessiond/user/1000/session").unwrap();
        svc.create(0, &root).unwrap();
        let a = ScopeId::parse("sessiond/user/1000/session/a").unwrap();
        let b = ScopeId::parse("sessiond/user/1000/session/b").unwrap();
        svc.create(0, &a).unwrap();
        svc.create(0, &b).unwrap();

        let mut listed = svc.list(0, &root).unwrap();
        listed.sort();
        assert_eq!(listed, vec![a, b]);
    }
}
