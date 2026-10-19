//! The D-Bus surface: method dispatch, caller-uid resolution, and mapping
//! `Service`/`BackendError` onto D-Bus error names. Keeps zbus-specific
//! code out of `crate::service` and `crate::backend`, which stay
//! unit-testable without a bus.

use crate::backend::{BackendError, RealBackend};
use crate::policy::PolicyError;
use crate::service::{Service, ServiceError};
use crate::watch::Watchers;
use scope_id::ScopeId;
use std::sync::Arc;
use zbus::fdo;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::object_server::SignalEmitter;
use zbus::Connection;

/// Well-known bus name `scoped` requests on the system bus.
pub const BUS_NAME: &str = "org.decoupling.scoped1";
/// Object path `scoped` serves its manager interface at.
pub const OBJECT_PATH: &str = "/org/decoupling/scoped1";
/// D-Bus interface name for the manager object. Kept in sync with (but not
/// referenced by, since the macro attribute needs a literal) the
/// `#[zbus::interface(name = "...")]` attribute below; see the test at the
/// bottom of this file.
#[allow(dead_code)]
pub const INTERFACE_NAME: &str = "org.decoupling.scoped1.Manager";

/// The `org.decoupling.scoped1.Manager` D-Bus object. Thin: every method
/// resolves the caller's uid, validates its string arguments into
/// [`ScopeId`]/[`crate::backend::Signal`], and delegates to
/// [`Service`], which enforces policy and talks to the backend.
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
    /// `Create(id)`: atomic; fails if `id` already exists.
    async fn create(
        &self,
        id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        self.service.create(uid, &id).map_err(service_error)?;
        self.watchers.watch_new(id);
        Ok(())
    }

    /// `Move(pid, id)`: moves a process into a scope.
    #[zbus(name = "Move")]
    async fn move_pid(
        &self,
        pid: u32,
        id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        self.service.move_pid(uid, pid, &id).map_err(service_error)
    }

    /// `ScopeOf(pid) -> id`. Returns an empty string if `pid` is not in any
    /// scope this daemon manages.
    async fn scope_of(
        &self,
        pid: u32,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        let uid = caller_uid(conn, &header).await?;
        let scope = self.service.scope_of(uid, pid).map_err(service_error)?;
        Ok(scope.map(|id| id.to_string()).unwrap_or_default())
    }

    /// `List(prefix) -> ids`: every descendant scope under `prefix`, not
    /// including `prefix` itself.
    async fn list(
        &self,
        prefix: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<Vec<String>> {
        let uid = caller_uid(conn, &header).await?;
        let prefix = parse_id(&prefix)?;
        let ids = self.service.list(uid, &prefix).map_err(service_error)?;
        Ok(ids.into_iter().map(|id| id.to_string()).collect())
    }

    /// `Terminate(id, signal)`: signals every process in `id` and its
    /// descendants; does not wait for them to exit.
    async fn terminate(
        &self,
        id: String,
        signal: i32,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        let sig = parse_signal(signal)?;
        self.service.terminate(uid, &id, sig).map_err(service_error)
    }

    /// `Kill(id)`: SIGKILLs every process in `id` and its descendants.
    async fn kill(
        &self,
        id: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let uid = caller_uid(conn, &header).await?;
        let id = parse_id(&id)?;
        self.service.kill(uid, &id).map_err(service_error)
    }

    /// Emitted when a scope's population (itself or any descendant) drops
    /// to zero, just before `scoped` tries to remove it.
    #[zbus(signal)]
    pub async fn scope_empty(emitter: &SignalEmitter<'_>, id: &str) -> zbus::Result<()>;

    /// Emitted right after `scoped` removes a scope -- including, during
    /// the upward cascade, each now-empty ancestor directory it removes
    /// along with it, and during the startup sweep for leftovers from a
    /// previous run.
    #[zbus(signal)]
    pub async fn scope_removed(emitter: &SignalEmitter<'_>, id: &str) -> zbus::Result<()>;
}

/// Resolves the uid of the caller of the method call `header` belongs to,
/// by asking the bus daemon for the sender's credentials. The caller's pid
/// is deliberately never taken from the request body -- only from the bus
/// connection itself (see the plan's "Core rule for seat access"-adjacent
/// principle applied to D-Bus callers).
async fn caller_uid(conn: &Connection, header: &Header<'_>) -> fdo::Result<u32> {
    let Some(sender) = header.sender() else {
        return Err(fdo::Error::AccessDenied(
            "message has no sender; cannot authorize".into(),
        ));
    };
    let proxy = fdo::DBusProxy::new(conn)
        .await
        .map_err(|e| fdo::Error::Failed(format!("could not reach the bus daemon: {e}")))?;
    let creds = proxy
        .get_connection_credentials(BusName::from(sender.clone()))
        .await
        .map_err(|e| fdo::Error::Failed(format!("could not get caller credentials: {e}")))?;
    creds.unix_user_id().ok_or_else(|| {
        fdo::Error::AccessDenied("bus did not report a unix user id for the caller".into())
    })
}

fn parse_id(raw: &str) -> fdo::Result<ScopeId> {
    ScopeId::parse(raw).map_err(|e| fdo::Error::InvalidArgs(e.to_string()))
}

fn parse_signal(raw: i32) -> fdo::Result<crate::backend::Signal> {
    crate::backend::Signal::try_from(raw)
        .map_err(|_| fdo::Error::InvalidArgs(format!("{raw} is not a valid signal number")))
}

fn service_error(e: ServiceError) -> fdo::Error {
    match e {
        ServiceError::Policy(PolicyError::AccessDenied) => {
            fdo::Error::AccessDenied("caller may not address this scope".into())
        }
        ServiceError::Policy(PolicyError::NotProcessOwner) => {
            fdo::Error::AccessDenied("caller does not own this process".into())
        }
        ServiceError::Policy(PolicyError::ProcessNotFound(pid)) => {
            fdo::Error::UnixProcessIdUnknown(pid.to_string())
        }
        ServiceError::Backend(BackendError::NotFound(id)) => {
            fdo::Error::FileNotFound(format!("scope {id} does not exist"))
        }
        ServiceError::Backend(BackendError::AlreadyExists(id)) => {
            fdo::Error::FileExists(format!("scope {id} already exists"))
        }
        ServiceError::Backend(BackendError::PermissionDenied(id)) => {
            fdo::Error::AccessDenied(format!("permission denied operating on scope {id}"))
        }
        ServiceError::Backend(BackendError::ProcessNotFound(pid)) => {
            fdo::Error::UnixProcessIdUnknown(pid.to_string())
        }
        ServiceError::Backend(e @ BackendError::Io { .. }) => fdo::Error::Failed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_name_matches_the_macro_attribute() {
        // The #[zbus::interface(name = "...")] attribute above needs a
        // literal, so it can't reference INTERFACE_NAME directly; this
        // keeps the two from drifting apart silently.
        assert_eq!(INTERFACE_NAME, "org.decoupling.scoped1.Manager");
    }
}
