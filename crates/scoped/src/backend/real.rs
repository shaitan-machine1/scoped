use super::{BackendError, CgroupBackend, Pid, ProcessHandle, TargetStatus};
use scope_id::{ScopeId, TargetId};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// A [`CgroupBackend`] backed by a real cgroup v2 filesystem.
///
/// `scoped` manages everything under `mount.join(scope_root)` (by default
/// `/sys/fs/cgroup/scoped`); `scope_root` must be a single path segment
/// directly under `mount`. Scope IDs map to directories under that root by
/// joining their `/`-separated segments as path components.
pub struct RealBackend {
    mount: PathBuf,
    scope_root: String,
    pub(super) target_lock: Mutex<()>,
}

/// How many times [`RealBackend::create`] retries after losing a benign
/// race with the empty-scope garbage collector (see `crate::watch`).
const CREATE_RETRIES: usize = 3;

/// Freezing is normally reflected immediately, but a bounded wait keeps a
/// wedged kernel/filesystem from hanging the D-Bus worker forever.
const FREEZE_TIMEOUT: Duration = Duration::from_secs(5);

impl RealBackend {
    /// Opens (creating if needed) `mount/scope_root` as the managed root.
    pub fn new(mount: PathBuf, scope_root: String) -> io::Result<Self> {
        scope_id::validate_segment(&scope_root)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let backend = RealBackend {
            mount,
            scope_root,
            target_lock: Mutex::new(()),
        };
        fs::create_dir_all(backend.base())?;
        Ok(backend)
    }

    /// The managed root directory, e.g. `/sys/fs/cgroup/scoped`.
    pub fn base(&self) -> PathBuf {
        self.mount.join(&self.scope_root)
    }

    /// The filesystem path of a scope id.
    pub fn fs_path(&self, id: &ScopeId) -> PathBuf {
        let mut p = self.base();
        for seg in id.segments() {
            p.push(seg);
        }
        p
    }

    /// The prefix `/proc/<pid>/cgroup` paths have when the process is
    /// inside our managed root, e.g. `/scoped`. This assumes `scoped` and
    /// the processes it manages share the same cgroup namespace as the
    /// real, host-wide cgroup2 mount -- true for a normal, non-containerized
    /// deployment, and documented as a limitation otherwise.
    fn cgroup_rel_prefix(&self) -> String {
        format!("/{}", self.scope_root)
    }

    /// Maps a filesystem path under `base()` back to its scope id, or
    /// `None` if `path` is exactly `base()` (which is not itself a valid
    /// `ScopeId`) or not under `base()` at all.
    pub fn id_for_path(&self, path: &Path) -> Option<ScopeId> {
        let rel = path.strip_prefix(self.base()).ok()?;
        if rel.as_os_str().is_empty() {
            return None;
        }
        let rel = rel
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        ScopeId::parse(&rel).ok()
    }

    /// Lists the direct subdirectory names of `path` (empty if `path`
    /// doesn't exist). Used both internally and by `crate::watch`'s
    /// startup sweep, which needs to walk the tree without going through
    /// `ScopeId` (a bare directory may be a not-yet-cleaned-up empty leaf).
    pub(crate) fn subdirs(path: &Path) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    out.push(name.to_owned());
                }
            }
        }
        Ok(out)
    }

    /// Recursively collects every descendant directory under `path`
    /// (relative to `base`), as scope ids relative to `base`.
    fn walk(&self, path: &Path, out: &mut Vec<ScopeId>) -> io::Result<()> {
        for name in Self::subdirs(path)? {
            let child = path.join(&name);
            if let Some(id) = self.id_for_path(&child) {
                out.push(id);
            }
            self.walk(&child, out)?;
        }
        Ok(())
    }

    fn parse_event(content: &str, path: &Path, name: &str) -> io::Result<bool> {
        for line in content.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() == Some(name) {
                return match fields.next() {
                    Some("0") => Ok(false),
                    Some("1") => Ok(true),
                    value => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid {name} value {value:?} in {}", path.display()),
                    )),
                };
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cgroup.events at {} has no {name} field", path.display()),
        ))
    }

    fn read_event_file(file: &mut File, path: &Path, name: &str) -> io::Result<bool> {
        file.seek(SeekFrom::Start(0))?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Self::parse_event(&content, path, name)
    }

    fn read_event(path: &Path, name: &str) -> io::Result<bool> {
        let mut file = File::open(path.join("cgroup.events"))?;
        Self::read_event_file(&mut file, path, name)
    }

    pub(crate) fn read_populated_file(file: &mut File, path: &Path) -> io::Result<bool> {
        Self::read_event_file(file, path, "populated")
    }

    pub(crate) fn read_populated(path: &Path) -> io::Result<bool> {
        Self::read_event(path, "populated")
    }

    fn read_frozen(path: &Path) -> io::Result<bool> {
        Self::read_event(path, "frozen")
    }

    fn wait_frozen(path: &Path) -> io::Result<()> {
        let deadline = Instant::now() + FREEZE_TIMEOUT;
        loop {
            if Self::read_frozen(path)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for {} to freeze", path.display()),
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn read_procs(path: &Path) -> io::Result<Vec<Pid>> {
        let content = fs::read_to_string(path.join("cgroup.procs"))?;
        Ok(content
            .lines()
            .filter_map(|l| l.trim().parse::<Pid>().ok())
            .collect())
    }
}

impl CgroupBackend for RealBackend {
    fn create(&self, id: &ScopeId) -> Result<(), BackendError> {
        let path = self.fs_path(id);
        let mut last_err = None;
        for _ in 0..CREATE_RETRIES {
            if let Some(parent) = path.parent() {
                if let Err(e) = fs::create_dir_all(parent) {
                    last_err = Some(e);
                    continue;
                }
            }
            match fs::create_dir(&path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(BackendError::AlreadyExists(id.clone()));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // Lost a race with the empty-scope GC removing a parent
                    // directory we just created. Retry from scratch.
                    last_err = Some(e);
                    continue;
                }
                Err(e) => return Err(BackendError::from_io(id, "mkdir", e)),
            }
        }
        Err(BackendError::from_io(
            id,
            "mkdir (exhausted retries)",
            last_err.unwrap_or_else(|| io::Error::other("unknown error")),
        ))
    }

    fn move_pid(
        &self,
        pid: Pid,
        id: &ScopeId,
        target: Option<&TargetId>,
    ) -> Result<(), BackendError> {
        // The cgroup API still consumes a numeric PID, so this cannot make
        // migration itself pidfd-atomic. Pinning before the write and
        // checking identity + membership afterwards does, however, detect a
        // target that exited during the operation and ensures a durable
        // target binding never points at a recycled PID.
        let handle = ProcessHandle::open(pid).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                BackendError::ProcessNotFound(pid)
            } else {
                BackendError::io(format!("pinning process {pid} for move"), e)
            }
        })?;
        let identity = handle.identity();
        let _guard = self.target_lock.lock().unwrap();
        if let Some(target) = target {
            self.prepare_target_move(id, target, &handle)?;
        }

        let path = self.fs_path(id).join("cgroup.procs");
        if let Err(e) = fs::write(&path, pid.to_string()) {
            if let Some(target) = target {
                self.abort_target_move(id, target, identity);
            }
            return Err(BackendError::from_io(id, "move pid", e));
        }

        let valid = handle
            .identity_still_matches()
            .map_err(|e| BackendError::io(format!("revalidating process {pid} after move"), e))?
            && matches!(self.scope_of(pid), Ok(Some(actual)) if actual == *id);
        if !valid {
            if let Some(target) = target {
                self.abort_target_move(id, target, identity);
            }
            return Err(BackendError::ProcessNotFound(pid));
        }
        if let Some(target) = target {
            if let Err(e) = self.activate_target_move(id, target, identity) {
                // The process is already in the destination, but exposing a
                // half-registered target would be worse than returning an
                // untracked move that the root caller can safely retry.
                self.abort_target_move(id, target, identity);
                return Err(e);
            }
        }
        Ok(())
    }

    fn scope_of(&self, pid: Pid) -> Result<Option<ScopeId>, BackendError> {
        let proc_path = format!("/proc/{pid}/cgroup");
        let content = match fs::read_to_string(&proc_path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(BackendError::ProcessNotFound(pid));
            }
            Err(e) => {
                return Err(BackendError::Io {
                    context: format!("reading {proc_path}"),
                    source: e,
                });
            }
        };
        let Some(line) = content.lines().find(|l| l.starts_with("0::")) else {
            return Ok(None);
        };
        let cg_path = &line[3..];
        let prefix = self.cgroup_rel_prefix();
        if cg_path == prefix {
            return Ok(None); // managed root itself is not a ScopeId
        }
        // Require a component boundary: `/scoped-other/...` is not under a
        // managed root named `/scoped`.
        let child_prefix = format!("{prefix}/");
        let Some(rest) = cg_path.strip_prefix(&child_prefix) else {
            return Ok(None);
        };
        Ok(ScopeId::parse(rest).ok())
    }

    fn list(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>, BackendError> {
        let path = self.fs_path(prefix);
        let mut out = Vec::new();
        self.walk(&path, &mut out)
            .map_err(|e| BackendError::from_io(prefix, "list", e))?;
        Ok(out)
    }

    fn target_exists(&self, id: &ScopeId, target: &TargetId) -> Result<bool, BackendError> {
        match self.target_status(id, target) {
            Ok(TargetStatus::Live(_)) => Ok(true),
            Ok(TargetStatus::Missing | TargetStatus::Gone) | Err(BackendError::NotFound(_)) => {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    fn terminate_target(&self, id: &ScopeId, target: &TargetId) -> Result<(), BackendError> {
        match self.target_status(id, target)? {
            TargetStatus::Missing => Err(BackendError::TargetNotFound {
                scope: id.clone(),
                target: target.clone(),
            }),
            TargetStatus::Gone => Err(BackendError::TargetGone {
                scope: id.clone(),
                target: target.clone(),
            }),
            TargetStatus::Live(handle) => handle.send_terminate().map_err(|e| {
                if e.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) {
                    BackendError::TargetGone {
                        scope: id.clone(),
                        target: target.clone(),
                    }
                } else {
                    BackendError::io(format!("terminate target {target} in scope {id}"), e)
                }
            }),
        }
    }

    fn kill_target(&self, id: &ScopeId, target: &TargetId) -> Result<(), BackendError> {
        match self.target_status(id, target)? {
            TargetStatus::Missing => Err(BackendError::TargetNotFound {
                scope: id.clone(),
                target: target.clone(),
            }),
            TargetStatus::Gone => Err(BackendError::TargetGone {
                scope: id.clone(),
                target: target.clone(),
            }),
            TargetStatus::Live(handle) => handle.send_kill().map_err(|e| {
                if e.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) {
                    BackendError::TargetGone {
                        scope: id.clone(),
                        target: target.clone(),
                    }
                } else {
                    BackendError::io(format!("kill target {target} in scope {id}"), e)
                }
            }),
        }
    }

    fn terminate_scope(&self, id: &ScopeId) -> Result<(), BackendError> {
        // This is the same global operation lock used by Move and target
        // metadata. While held, no scoped API call can migrate a process into
        // the subtree between freezing and enumeration.
        let _guard = self.target_lock.lock().unwrap();
        let root = self.fs_path(id);
        let freeze = root.join("cgroup.freeze");
        match fs::write(&freeze, "1") {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(BackendError::from_io(id, "freeze scope", e)),
        }

        let mut first_error = None;
        let mut handles = Vec::new();

        if let Err(e) = Self::wait_frozen(&root) {
            first_error = Some(BackendError::from_io(id, "wait for frozen scope", e));
        } else {
            let mut scopes = vec![id.clone()];
            if let Err(e) = self.walk(&root, &mut scopes) {
                first_error = Some(BackendError::from_io(id, "enumerate frozen scope", e));
            }

            for scope in scopes {
                let path = self.fs_path(&scope);
                let pids = match Self::read_procs(&path) {
                    Ok(pids) => pids,
                    // Empty descendants can be removed by their watcher while
                    // the populated ancestor remains frozen.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        if first_error.is_none() {
                            first_error =
                                Some(BackendError::from_io(id, "read frozen scope members", e));
                        }
                        continue;
                    }
                };
                for pid in pids {
                    match ProcessHandle::open(pid) {
                        Ok(handle) => handles.push(handle),
                        // A process can finish while the freeze request is
                        // converging. It is no longer a member to terminate.
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => {
                            if first_error.is_none() {
                                first_error = Some(BackendError::io(
                                    format!("pinning process {pid} in frozen scope {id}"),
                                    e,
                                ));
                            }
                        }
                    }
                }
            }

            // Queue all signals before thawing. Frozen tasks cannot handle
            // SIGTERM or fork an escaping child until the cleanup below.
            for handle in handles {
                if let Err(e) = handle.send_terminate() {
                    if e.raw_os_error() != Some(rustix::io::Errno::SRCH.raw_os_error())
                        && first_error.is_none()
                    {
                        first_error = Some(BackendError::io(
                            format!("terminate process {} in scope {id}", handle.identity().pid),
                            e,
                        ));
                    }
                }
            }
        }

        // Never leave callers frozen, even when enumeration or signalling
        // failed. Preserve the first operation error unless thawing is the
        // only failure.
        if let Err(e) = fs::write(&freeze, "0") {
            if first_error.is_none() {
                first_error = Some(BackendError::from_io(id, "thaw scope", e));
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn kill_scope(&self, id: &ScopeId) -> Result<(), BackendError> {
        let path = self.fs_path(id).join("cgroup.kill");
        match fs::write(&path, "1") {
            Ok(()) => Ok(()),
            // Teardown is idempotent: an already-empty scope may be removed
            // between ScopePopulated and KillScope.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BackendError::from_io(id, "kill scope", e)),
        }
    }

    fn is_populated(&self, id: &ScopeId) -> Result<bool, BackendError> {
        match Self::read_populated(&self.fs_path(id)) {
            Ok(populated) => Ok(populated),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(BackendError::from_io(id, "is_populated", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    //! These tests exercise directory-structure logic only (path mapping,
    //! recursive `mkdir`/listing, parsing hand-written `cgroup.events` /
    //! `cgroup.procs` files) against a plain tmpdir. They intentionally do
    //! *not* test real cgroup v2 semantics: a tmpdir doesn't enforce
    //! EBUSY-on-populated-rmdir, doesn't auto-update `cgroup.events`, and
    //! `cgroup.kill` isn't a magic file there. That coverage lives in
    //! `tests/e2e.rs`, which needs root and a real cgroup2 mount.
    use super::*;

    fn backend(tmp: &tempfile::TempDir) -> RealBackend {
        RealBackend::new(tmp.path().to_path_buf(), "scoped".to_string()).unwrap()
    }

    #[test]
    fn new_creates_the_base_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        assert_eq!(b.base(), tmp.path().join("scoped"));
        assert!(b.base().is_dir());
    }

    #[test]
    fn create_makes_parents_and_rejects_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("sessiond/user/1000/session/abc").unwrap();
        b.create(&id).unwrap();
        assert!(b.fs_path(&id).is_dir());
        // Intermediate directories exist too.
        assert!(b.base().join("sessiond/user/1000/session").is_dir());

        match b.create(&id) {
            Err(BackendError::AlreadyExists(got)) => assert_eq!(got, id),
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn fs_path_and_id_for_path_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        let path = b.fs_path(&id);
        assert_eq!(path, b.base().join("user").join("1000").join("sandbox"));
        assert_eq!(b.id_for_path(&path), Some(id));
        assert_eq!(b.id_for_path(&b.base()), None);
    }

    #[test]
    fn list_returns_descendants_not_the_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let root = ScopeId::parse("sessiond/user/1000/session").unwrap();
        let a = ScopeId::parse("sessiond/user/1000/session/a").unwrap();
        let c = ScopeId::parse("sessiond/user/1000/session/a/nested").unwrap();
        b.create(&a).unwrap();
        b.create(&c).unwrap();

        let mut listed = b.list(&root).unwrap();
        listed.sort();
        let mut expected = vec![a, c];
        expected.sort();
        assert_eq!(listed, expected);
    }

    #[test]
    fn exists_is_false_for_missing_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        assert!(!b.fs_path(&id).is_dir());
    }

    #[test]
    fn read_populated_and_frozen_parse_cgroup_events() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        b.create(&id).unwrap();
        let path = b.fs_path(&id);
        let events_path = path.join("cgroup.events");
        fs::write(&events_path, "populated 0\nfrozen 1\n").unwrap();
        assert!(!b.is_populated(&id).unwrap());
        assert!(RealBackend::read_frozen(&path).unwrap());

        let mut file = File::open(&events_path).unwrap();
        assert!(!RealBackend::read_populated_file(&mut file, &path).unwrap());
        assert_eq!(
            file.stream_position().unwrap(),
            fs::metadata(&events_path).unwrap().len()
        );
        fs::write(&events_path, "populated 1\nfrozen 0\n").unwrap();
        assert!(RealBackend::read_populated_file(&mut file, &path).unwrap());
        assert!(b.is_populated(&id).unwrap());
        assert!(!RealBackend::read_frozen(&path).unwrap());
    }

    #[test]
    fn event_parser_rejects_missing_and_invalid_values() {
        let path = Path::new("/test/scope");
        assert!(RealBackend::parse_event("frozen 0\n", path, "populated").is_err());
        assert!(RealBackend::parse_event("populated 2\n", path, "populated").is_err());
        assert!(RealBackend::parse_event("populated\n", path, "populated").is_err());
    }

    #[test]
    fn terminate_scope_thaws_after_a_freeze_state_error() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        b.create(&id).unwrap();
        let path = b.fs_path(&id);
        fs::write(path.join("cgroup.freeze"), "0").unwrap();
        fs::write(path.join("cgroup.events"), "populated 1\n").unwrap();

        assert!(matches!(
            b.terminate_scope(&id),
            Err(BackendError::Io { .. })
        ));
        assert_eq!(
            fs::read_to_string(path.join("cgroup.freeze"))
                .unwrap()
                .trim(),
            "0"
        );
    }

    #[test]
    fn terminate_scope_is_idempotent_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/missing").unwrap();
        b.terminate_scope(&id).unwrap();
    }

    #[test]
    fn members_parses_cgroup_procs() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        b.create(&id).unwrap();
        fs::write(b.fs_path(&id).join("cgroup.procs"), "123\n456\n").unwrap();
        let mut members = RealBackend::read_procs(&b.fs_path(&id)).unwrap();
        members.sort();
        assert_eq!(members, vec![123, 456]);
    }

    #[test]
    fn move_pid_into_missing_scope_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        match b.move_pid(1, &id, None) {
            Err(BackendError::NotFound(got)) => assert_eq!(got, id),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
