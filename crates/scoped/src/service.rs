//! Root-only, platform-independent scoped service logic.

use crate::backend::{BackendError, CgroupBackend, Pid};
use crate::policy::{self, PolicyError};
use scope_id::{ScopeId, TargetId};
use std::fmt;

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

pub struct Service<B: CgroupBackend> {
    backend: B,
}

impl<B: CgroupBackend> Service<B> {
    pub fn new(backend: B) -> Self {
        Service { backend }
    }

    #[allow(dead_code)]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn create(&self, caller_uid: u32, id: &ScopeId) -> Result<(), ServiceError> {
        policy::check_root(caller_uid)?;
        self.backend.create(id)?;
        Ok(())
    }

    pub fn move_pid(
        &self,
        caller_uid: u32,
        pid: Pid,
        id: &ScopeId,
        target: Option<&TargetId>,
    ) -> Result<(), ServiceError> {
        policy::check_root(caller_uid)?;
        self.backend.move_pid(pid, id, target)?;
        Ok(())
    }

    pub fn scope_of(&self, caller_uid: u32, pid: Pid) -> Result<Option<ScopeId>, ServiceError> {
        policy::check_root(caller_uid)?;
        Ok(self.backend.scope_of(pid)?)
    }

    pub fn list(&self, caller_uid: u32, prefix: &ScopeId) -> Result<Vec<ScopeId>, ServiceError> {
        policy::check_root(caller_uid)?;
        Ok(self.backend.list(prefix)?)
    }

    pub fn target_exists(
        &self,
        caller_uid: u32,
        id: &ScopeId,
        target: &TargetId,
    ) -> Result<bool, ServiceError> {
        policy::check_root(caller_uid)?;
        Ok(self.backend.target_exists(id, target)?)
    }

    pub fn scope_populated(&self, caller_uid: u32, id: &ScopeId) -> Result<bool, ServiceError> {
        policy::check_root(caller_uid)?;
        Ok(self.backend.is_populated(id)?)
    }

    pub fn terminate_target(
        &self,
        caller_uid: u32,
        id: &ScopeId,
        target: &TargetId,
    ) -> Result<(), ServiceError> {
        policy::check_root(caller_uid)?;
        self.backend.terminate_target(id, target)?;
        Ok(())
    }

    pub fn kill_target(
        &self,
        caller_uid: u32,
        id: &ScopeId,
        target: &TargetId,
    ) -> Result<(), ServiceError> {
        policy::check_root(caller_uid)?;
        self.backend.kill_target(id, target)?;
        Ok(())
    }

    pub fn terminate_scope(&self, caller_uid: u32, id: &ScopeId) -> Result<(), ServiceError> {
        policy::check_root(caller_uid)?;
        self.backend.terminate_scope(id)?;
        Ok(())
    }

    pub fn kill_scope(&self, caller_uid: u32, id: &ScopeId) -> Result<(), ServiceError> {
        policy::check_root(caller_uid)?;
        self.backend.kill_scope(id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeBackend {
        scopes: Mutex<BTreeSet<ScopeId>>,
        pid_scope: Mutex<HashMap<Pid, ScopeId>>,
        targets: Mutex<HashMap<(ScopeId, TargetId), Pid>>,
    }

    impl CgroupBackend for FakeBackend {
        fn create(&self, id: &ScopeId) -> Result<(), BackendError> {
            if !self.scopes.lock().unwrap().insert(id.clone()) {
                return Err(BackendError::AlreadyExists(id.clone()));
            }
            Ok(())
        }

        fn move_pid(
            &self,
            pid: Pid,
            id: &ScopeId,
            target: Option<&TargetId>,
        ) -> Result<(), BackendError> {
            if !self.scopes.lock().unwrap().contains(id) {
                return Err(BackendError::NotFound(id.clone()));
            }
            self.pid_scope.lock().unwrap().insert(pid, id.clone());
            if let Some(target) = target {
                let key = (id.clone(), target.clone());
                let mut targets = self.targets.lock().unwrap();
                if let Some(existing) = targets.get(&key) {
                    if *existing != pid {
                        return Err(BackendError::TargetAlreadyExists {
                            scope: id.clone(),
                            target: target.clone(),
                        });
                    }
                }
                targets.insert(key, pid);
            }
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

        fn target_exists(&self, id: &ScopeId, target: &TargetId) -> Result<bool, BackendError> {
            Ok(self
                .targets
                .lock()
                .unwrap()
                .contains_key(&(id.clone(), target.clone())))
        }

        fn terminate_target(&self, id: &ScopeId, target: &TargetId) -> Result<(), BackendError> {
            if self.target_exists(id, target)? {
                Ok(())
            } else {
                Err(BackendError::TargetNotFound {
                    scope: id.clone(),
                    target: target.clone(),
                })
            }
        }

        fn kill_target(&self, id: &ScopeId, target: &TargetId) -> Result<(), BackendError> {
            self.terminate_target(id, target)
        }

        fn terminate_scope(&self, _id: &ScopeId) -> Result<(), BackendError> {
            Ok(())
        }

        fn kill_scope(&self, _id: &ScopeId) -> Result<(), BackendError> {
            Ok(())
        }

        fn is_populated(&self, id: &ScopeId) -> Result<bool, BackendError> {
            Ok(self
                .pid_scope
                .lock()
                .unwrap()
                .values()
                .any(|scope| scope.is_or_is_under(id)))
        }
    }

    fn ids() -> (ScopeId, TargetId) {
        (
            ScopeId::parse("sessiond/user/1000/service").unwrap(),
            TargetId::parse("manager").unwrap(),
        )
    }

    #[test]
    fn every_operation_is_root_only() {
        let svc = Service::new(FakeBackend::default());
        let (scope, target) = ids();
        assert!(matches!(
            svc.create(1000, &scope),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.scope_populated(1000, &scope),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.target_exists(1000, &scope, &target),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.move_pid(1000, 42, &scope, Some(&target)),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.scope_of(1000, 42),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.list(1000, &scope),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.terminate_target(1000, &scope, &target),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.kill_target(1000, &scope, &target),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.terminate_scope(1000, &scope),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
        assert!(matches!(
            svc.kill_scope(1000, &scope),
            Err(ServiceError::Policy(PolicyError::AccessDenied))
        ));
    }

    #[test]
    fn tracked_move_is_idempotent_for_the_same_process() {
        let svc = Service::new(FakeBackend::default());
        let (scope, target) = ids();
        svc.create(0, &scope).unwrap();
        svc.move_pid(0, 42, &scope, Some(&target)).unwrap();
        svc.move_pid(0, 42, &scope, Some(&target)).unwrap();
        assert!(svc.target_exists(0, &scope, &target).unwrap());
        assert_eq!(svc.scope_of(0, 42).unwrap(), Some(scope));
    }

    #[test]
    fn tracked_move_rejects_a_live_target_collision() {
        let svc = Service::new(FakeBackend::default());
        let (scope, target) = ids();
        svc.create(0, &scope).unwrap();
        svc.move_pid(0, 42, &scope, Some(&target)).unwrap();
        assert!(matches!(
            svc.move_pid(0, 43, &scope, Some(&target)),
            Err(ServiceError::Backend(
                BackendError::TargetAlreadyExists { .. }
            ))
        ));
    }

    #[test]
    fn untracked_move_creates_no_target() {
        let svc = Service::new(FakeBackend::default());
        let (scope, target) = ids();
        svc.create(0, &scope).unwrap();
        svc.move_pid(0, 42, &scope, None).unwrap();
        assert!(!svc.target_exists(0, &scope, &target).unwrap());
        assert!(svc.scope_populated(0, &scope).unwrap());
    }

    #[test]
    fn list_excludes_the_prefix() {
        let svc = Service::new(FakeBackend::default());
        let root = ScopeId::parse("sessiond/user/1000/session").unwrap();
        let child = root.join("abc").unwrap();
        svc.create(0, &root).unwrap();
        svc.create(0, &child).unwrap();
        assert_eq!(svc.list(0, &root).unwrap(), vec![child]);
    }
}
