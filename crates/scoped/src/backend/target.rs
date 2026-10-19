//! Durable tracked-target records stored as cgroup-directory xattrs.

use super::{BackendError, CgroupBackend, ProcessHandle, ProcessIdentity, RealBackend};
use scope_id::{ScopeId, TargetId};
use std::io;

const XATTR_PREFIX: &str = "user.scoped.target.";
const RECORD_VERSION: &str = "v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordState {
    Pending,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TargetRecord {
    state: RecordState,
    identity: ProcessIdentity,
}

impl TargetRecord {
    fn encode(self) -> String {
        let state = match self.state {
            RecordState::Pending => "pending",
            RecordState::Active => "active",
        };
        format!(
            "{RECORD_VERSION}:{state}:{}:{}",
            self.identity.pid, self.identity.start_time
        )
    }

    fn parse(raw: &[u8]) -> io::Result<Self> {
        let raw =
            std::str::from_utf8(raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut fields = raw.split(':');
        let version = fields.next();
        let state = fields.next();
        let pid = fields.next();
        let start_time = fields.next();
        if version != Some(RECORD_VERSION) || fields.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported target record {raw:?}"),
            ));
        }
        let state = match state {
            Some("pending") => RecordState::Pending,
            Some("active") => RecordState::Active,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid target record state in {raw:?}"),
                ));
            }
        };
        let pid = pid
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target record has no pid"))?
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let start_time = start_time
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "target record has no start time",
                )
            })?
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(TargetRecord {
            state,
            identity: ProcessIdentity { pid, start_time },
        })
    }
}

#[derive(Debug)]
pub enum TargetStatus {
    Missing,
    Gone,
    Live(ProcessHandle),
}

impl RealBackend {
    fn target_xattr(target: &TargetId) -> String {
        format!("{XATTR_PREFIX}{target}")
    }

    fn target_context(id: &ScopeId, target: &TargetId, action: &str) -> String {
        format!("{action} target {target} in scope {id}")
    }

    fn read_target_record_unlocked(
        &self,
        id: &ScopeId,
        target: &TargetId,
    ) -> Result<Option<TargetRecord>, BackendError> {
        let path = self.fs_path(id);
        let name = Self::target_xattr(target);
        let raw = xattr::get(&path, &name).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                BackendError::NotFound(id.clone())
            } else {
                BackendError::io(Self::target_context(id, target, "read"), e)
            }
        })?;
        raw.map(|raw| {
            TargetRecord::parse(&raw)
                .map_err(|e| BackendError::io(Self::target_context(id, target, "parse"), e))
        })
        .transpose()
    }

    fn write_target_record_unlocked(
        &self,
        id: &ScopeId,
        target: &TargetId,
        record: TargetRecord,
    ) -> Result<(), BackendError> {
        let path = self.fs_path(id);
        let name = Self::target_xattr(target);
        xattr::set(path, name, record.encode().as_bytes()).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                BackendError::NotFound(id.clone())
            } else {
                BackendError::io(Self::target_context(id, target, "write"), e)
            }
        })
    }

    fn remove_target_record_unlocked(
        &self,
        id: &ScopeId,
        target: &TargetId,
    ) -> Result<(), BackendError> {
        let path = self.fs_path(id);
        let name = Self::target_xattr(target);
        match xattr::remove(path, name) {
            Ok(()) => Ok(()),
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(rustix::io::Errno::NODATA.raw_os_error()) =>
            {
                Ok(())
            }
            Err(e) => Err(BackendError::io(
                Self::target_context(id, target, "remove"),
                e,
            )),
        }
    }

    fn target_ids_unlocked(&self, id: &ScopeId) -> Result<Vec<TargetId>, BackendError> {
        let path = self.fs_path(id);
        let attrs = xattr::list(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                BackendError::NotFound(id.clone())
            } else {
                BackendError::io(format!("list targets in scope {id}"), e)
            }
        })?;
        Ok(attrs
            .filter_map(|name| name.into_string().ok())
            .filter_map(|name| name.strip_prefix(XATTR_PREFIX).map(str::to_owned))
            .filter_map(|name| TargetId::parse(name).ok())
            .collect())
    }

    fn target_status_unlocked(
        &self,
        id: &ScopeId,
        target: &TargetId,
    ) -> Result<TargetStatus, BackendError> {
        let Some(record) = self.read_target_record_unlocked(id, target)? else {
            return Ok(TargetStatus::Missing);
        };
        let handle = match ProcessHandle::open(record.identity.pid) {
            Ok(handle) => handle,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(TargetStatus::Gone),
            Err(e) => {
                return Err(BackendError::io(
                    Self::target_context(id, target, "open process handle for"),
                    e,
                ));
            }
        };
        if handle.identity() != record.identity
            || !handle.identity_still_matches().map_err(|e| {
                BackendError::io(Self::target_context(id, target, "validate identity for"), e)
            })?
        {
            return Ok(TargetStatus::Gone);
        }
        match <Self as CgroupBackend>::scope_of(self, record.identity.pid) {
            Ok(Some(actual)) if actual == *id => {}
            Ok(_) | Err(BackendError::ProcessNotFound(_)) => return Ok(TargetStatus::Gone),
            Err(e) => return Err(e),
        }
        if record.state == RecordState::Pending {
            self.write_target_record_unlocked(
                id,
                target,
                TargetRecord {
                    state: RecordState::Active,
                    ..record
                },
            )?;
        }
        Ok(TargetStatus::Live(handle))
    }

    pub(crate) fn target_status(
        &self,
        id: &ScopeId,
        target: &TargetId,
    ) -> Result<TargetStatus, BackendError> {
        let _guard = self.target_lock.lock().unwrap();
        self.target_status_unlocked(id, target)
    }

    pub(crate) fn target_ids(&self, id: &ScopeId) -> Result<Vec<TargetId>, BackendError> {
        let _guard = self.target_lock.lock().unwrap();
        self.target_ids_unlocked(id)
    }

    pub(crate) fn prepare_target_move(
        &self,
        id: &ScopeId,
        target: &TargetId,
        handle: &ProcessHandle,
    ) -> Result<(), BackendError> {
        match self.target_status_unlocked(id, target)? {
            TargetStatus::Missing | TargetStatus::Gone => {}
            TargetStatus::Live(existing) if existing.identity() == handle.identity() => {}
            TargetStatus::Live(_) => {
                return Err(BackendError::TargetAlreadyExists {
                    scope: id.clone(),
                    target: target.clone(),
                });
            }
        }
        for existing_id in self.target_ids_unlocked(id)? {
            if existing_id == *target {
                continue;
            }
            if let TargetStatus::Live(existing) = self.target_status_unlocked(id, &existing_id)? {
                if existing.identity() == handle.identity() {
                    return Err(BackendError::ProcessAlreadyTracked {
                        scope: id.clone(),
                        target: existing_id,
                    });
                }
            }
        }
        self.write_target_record_unlocked(
            id,
            target,
            TargetRecord {
                state: RecordState::Pending,
                identity: handle.identity(),
            },
        )
    }

    pub(crate) fn activate_target_move(
        &self,
        id: &ScopeId,
        target: &TargetId,
        identity: ProcessIdentity,
    ) -> Result<(), BackendError> {
        self.write_target_record_unlocked(
            id,
            target,
            TargetRecord {
                state: RecordState::Active,
                identity,
            },
        )
    }

    pub(crate) fn abort_target_move(
        &self,
        id: &ScopeId,
        target: &TargetId,
        identity: ProcessIdentity,
    ) {
        if matches!(
            self.read_target_record_unlocked(id, target),
            Ok(Some(record)) if record.identity == identity
        ) {
            let _ = self.remove_target_record_unlocked(id, target);
        }
    }

    /// Removes a binding only if it still refers to the watcher process.
    /// This prevents a delayed old watcher from deleting a replacement that
    /// reused the same target ID.
    pub(crate) fn remove_target_if(
        &self,
        id: &ScopeId,
        target: &TargetId,
        identity: ProcessIdentity,
    ) -> Result<bool, BackendError> {
        let _guard = self.target_lock.lock().unwrap();
        let Some(record) = self.read_target_record_unlocked(id, target)? else {
            return Ok(false);
        };
        if record.identity != identity {
            return Ok(false);
        }
        self.remove_target_record_unlocked(id, target)?;
        Ok(true)
    }

    pub(crate) fn remove_stale_target(
        &self,
        id: &ScopeId,
        target: &TargetId,
    ) -> Result<(), BackendError> {
        let _guard = self.target_lock.lock().unwrap();
        if matches!(self.target_status_unlocked(id, target)?, TargetStatus::Gone) {
            self.remove_target_record_unlocked(id, target)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_record_roundtrips() {
        for state in [RecordState::Pending, RecordState::Active] {
            let record = TargetRecord {
                state,
                identity: ProcessIdentity {
                    pid: 1234,
                    start_time: 987_654,
                },
            };
            assert_eq!(
                TargetRecord::parse(record.encode().as_bytes()).unwrap(),
                record
            );
        }
    }

    #[test]
    fn target_record_rejects_unknown_or_malformed_data() {
        for raw in [
            b"v2:active:1:2".as_slice(),
            b"v1:other:1:2",
            b"v1:active:no:2",
            b"v1:active:1",
            b"v1:active:1:2:extra",
        ] {
            assert!(TargetRecord::parse(raw).is_err(), "accepted {raw:?}");
        }
    }
}
