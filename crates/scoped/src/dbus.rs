//! D-Bus dispatch, root authorization credentials, and error mapping.

use crate::backend::{BackendError, RealBackend};
use crate::policy::PolicyError;
use crate::service::{Service, ServiceError};
use crate::watch::Watchers;
use scope_id::{ScopeId, TargetId};
pub use scoped_api::{BUS_NAME, OBJECT_PATH};
use std::sync::Arc;
use zbus::fdo;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::object_server::SignalEmitter;
use zbus::Connection;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.decoupling.scoped1.Error")]
enum ManagerError {
    AccessDenied(String),
    InvalidScopeId(String),
    InvalidTargetId(String),
    ScopeNotFound(String),
    ScopeAlreadyExists(String),
    ProcessNotFound(String),
    TargetAlreadyExists(String),
    TargetNotFound(String),
    TargetGone(String),
    BackendFailure(String),
}

pub struct Manager {
    service: Arc<Service<Arc<RealBackend>>>,
    watchers: Watchers,
}

impl Manager {
    pub fn new(service: Arc<Service<Arc<RealBackend>>>, watchers: Watchers) -> Self {
        Manager { service, watchers }
    }
}

#[zbus::interface(name = "org.decoupling.scoped1.Manager")]
impl Manager {
    async fn create(
        &self,
        id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        self.service.create(uid, &id).map_err(service_error)?;
        self.watchers.watch_new(id);
        Ok(())
    }

    /// Moves `pid` and, when `target_id` is non-empty, durably tracks that
    /// exact process instance under the scope-local target ID.
    #[zbus(name = "Move")]
    async fn move_pid(
        &self,
        pid: u32,
        id: String,
        target_id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        let target = parse_optional_target(&target_id)?;
        self.service
            .move_pid(uid, pid, &id, target.as_ref())
            .map_err(service_error)?;
        if let Some(target) = target {
            self.watchers.watch_target(id, target);
        }
        Ok(())
    }

    async fn scope_of(
        &self,
        pid: u32,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<String, ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let scope = self.service.scope_of(uid, pid).map_err(service_error)?;
        Ok(scope.map(String::from).unwrap_or_default())
    }

    async fn list(
        &self,
        prefix: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<Vec<String>, ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let prefix = parse_id(&prefix)?;
        let ids = self.service.list(uid, &prefix).map_err(service_error)?;
        Ok(ids.into_iter().map(String::from).collect())
    }

    async fn target_exists(
        &self,
        id: String,
        target_id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<bool, ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        let target = parse_target(&target_id)?;
        self.service
            .target_exists(uid, &id, &target)
            .map_err(service_error)
    }

    async fn scope_populated(
        &self,
        id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<bool, ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        self.service
            .scope_populated(uid, &id)
            .map_err(service_error)
    }

    async fn terminate_target(
        &self,
        id: String,
        target_id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        let target = parse_target(&target_id)?;
        self.service
            .terminate_target(uid, &id, &target)
            .map_err(service_error)
    }

    async fn kill_target(
        &self,
        id: String,
        target_id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        let target = parse_target(&target_id)?;
        self.service
            .kill_target(uid, &id, &target)
            .map_err(service_error)
    }

    async fn terminate_scope(
        &self,
        id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        self.service
            .terminate_scope(uid, &id)
            .map_err(service_error)
    }

    async fn kill_scope(
        &self,
        id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), ManagerError> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        self.service.kill_scope(uid, &id).map_err(service_error)
    }

    #[zbus(signal)]
    pub async fn target_gone(
        emitter: &SignalEmitter<'_>,
        id: &str,
        target_id: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn scope_empty(emitter: &SignalEmitter<'_>, id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn scope_removed(emitter: &SignalEmitter<'_>, id: &str) -> zbus::Result<()>;
}

async fn caller_uid(conn: &Connection, header: &Header<'_>) -> Result<u32, ManagerError> {
    let Some(sender) = header.sender() else {
        return Err(ManagerError::AccessDenied(
            "message has no sender; cannot authorize".into(),
        ));
    };
    let proxy = fdo::DBusProxy::new(conn)
        .await
        .map_err(|e| ManagerError::BackendFailure(format!("could not reach bus daemon: {e}")))?;
    let creds = proxy
        .get_connection_credentials(BusName::from(sender.clone()))
        .await
        .map_err(|e| {
            ManagerError::BackendFailure(format!("could not get caller credentials: {e}"))
        })?;
    creds.unix_user_id().ok_or_else(|| {
        ManagerError::AccessDenied("bus did not report a unix user id for the caller".into())
    })
}

fn parse_id(raw: &str) -> Result<ScopeId, ManagerError> {
    ScopeId::parse(raw).map_err(|e| ManagerError::InvalidScopeId(e.to_string()))
}

fn parse_target(raw: &str) -> Result<TargetId, ManagerError> {
    TargetId::parse(raw).map_err(|e| ManagerError::InvalidTargetId(e.to_string()))
}

fn parse_optional_target(raw: &str) -> Result<Option<TargetId>, ManagerError> {
    if raw.is_empty() {
        Ok(None)
    } else {
        parse_target(raw).map(Some)
    }
}

fn service_error(e: ServiceError) -> ManagerError {
    match e {
        ServiceError::Policy(PolicyError::AccessDenied) => {
            ManagerError::AccessDenied("scoped is root-only".into())
        }
        ServiceError::Backend(BackendError::NotFound(id)) => {
            ManagerError::ScopeNotFound(format!("scope {id} does not exist"))
        }
        ServiceError::Backend(BackendError::AlreadyExists(id)) => {
            ManagerError::ScopeAlreadyExists(format!("scope {id} already exists"))
        }
        ServiceError::Backend(BackendError::PermissionDenied(id)) => {
            ManagerError::AccessDenied(format!("permission denied operating on scope {id}"))
        }
        ServiceError::Backend(BackendError::ProcessNotFound(pid)) => {
            ManagerError::ProcessNotFound(format!("process {pid} does not exist"))
        }
        ServiceError::Backend(BackendError::TargetAlreadyExists { scope, target }) => {
            ManagerError::TargetAlreadyExists(format!(
                "target {target} already names a live process in scope {scope}"
            ))
        }
        ServiceError::Backend(BackendError::ProcessAlreadyTracked { scope, target }) => {
            ManagerError::TargetAlreadyExists(format!(
                "process is already tracked as {target} in scope {scope}"
            ))
        }
        ServiceError::Backend(BackendError::TargetNotFound { scope, target }) => {
            ManagerError::TargetNotFound(format!("target {target} does not exist in scope {scope}"))
        }
        ServiceError::Backend(BackendError::TargetGone { scope, target }) => {
            ManagerError::TargetGone(format!(
                "target {target} is no longer alive in scope {scope}"
            ))
        }
        ServiceError::Backend(e @ BackendError::Io { .. }) => {
            ManagerError::BackendFailure(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_name_matches_the_macro_attribute() {
        assert_eq!(scoped_api::INTERFACE_NAME, "org.decoupling.scoped1.Manager");
    }

    #[test]
    fn empty_move_target_means_untracked() {
        assert_eq!(parse_optional_target("").unwrap(), None);
        assert_eq!(
            parse_optional_target("manager").unwrap().unwrap().as_str(),
            "manager"
        );
    }
}
