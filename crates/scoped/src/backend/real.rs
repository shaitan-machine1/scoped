use super::{BackendError, CgroupBackend, Pid, Signal};
use scope_id::ScopeId;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A [`CgroupBackend`] backed by a real cgroup v2 filesystem.
///
/// `scoped` manages everything under `mount.join(scope_root)` (by default
/// `/sys/fs/cgroup/scoped`); `scope_root` must be a single path segment
/// directly under `mount`. Scope IDs map to directories under that root by
/// joining their `/`-separated segments as path components.
pub struct RealBackend {
    mount: PathBuf,
    scope_root: String,
}

/// How many times [`RealBackend::create`] retries after losing a benign
/// race with the empty-scope garbage collector (see `crate::watch`).
const CREATE_RETRIES: usize = 3;

impl RealBackend {
    /// Opens (creating if needed) `mount/scope_root` as the managed root.
    pub fn new(mount: PathBuf, scope_root: String) -> io::Result<Self> {
        scope_id::validate_segment(&scope_root)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let backend = RealBackend { mount, scope_root };
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

    pub(crate) fn read_populated(path: &Path) -> io::Result<bool> {
        let content = fs::read_to_string(path.join("cgroup.events"))?;
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("populated ") {
                return Ok(v.trim() == "1");
            }
        }
        Ok(false)
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

    fn exists(&self, id: &ScopeId) -> Result<bool, BackendError> {
        Ok(self.fs_path(id).is_dir())
    }

    fn move_pid(&self, pid: Pid, id: &ScopeId) -> Result<(), BackendError> {
        let path = self.fs_path(id).join("cgroup.procs");
        fs::write(&path, pid.to_string()).map_err(|e| BackendError::from_io(id, "move pid", e))
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
        let Some(rest) = cg_path.strip_prefix(&prefix) else {
            return Ok(None);
        };
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        if rest.is_empty() {
            return Ok(None);
        }
        Ok(ScopeId::parse(rest).ok())
    }

    fn list(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>, BackendError> {
        let path = self.fs_path(prefix);
        let mut out = Vec::new();
        self.walk(&path, &mut out)
            .map_err(|e| BackendError::from_io(prefix, "list", e))?;
        Ok(out)
    }

    fn members(&self, id: &ScopeId) -> Result<Vec<Pid>, BackendError> {
        Self::read_procs(&self.fs_path(id)).map_err(|e| BackendError::from_io(id, "members", e))
    }

    /// Signals every member of `id` and its descendants, one pid at a
    /// time.
    ///
    /// Inherently racy, in two ways the kernel gives us no way to avoid
    /// for an arbitrary signal (`cgroup.kill`, used by
    /// [`CgroupBackend::kill`], is atomic but SIGKILL-only):
    ///
    /// - a process that forks while we're walking the list may not be
    ///   signalled at all;
    /// - a pid that exits between being read out of `cgroup.procs` and
    ///   being signalled may have been recycled, so the signal lands on an
    ///   unrelated process.
    ///
    /// Freezing the cgroup (`cgroup.freeze`) around the walk would close
    /// both; see the README's "Known limitations".
    fn terminate(&self, id: &ScopeId, signal: Signal) -> Result<(), BackendError> {
        let mut pids = self.members(id)?;
        for descendant in self.list(id)? {
            pids.extend(self.members(&descendant)?);
        }
        for pid in pids {
            // Best-effort: a process that already exited is not an error.
            let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), signal);
        }
        Ok(())
    }

    fn kill(&self, id: &ScopeId) -> Result<(), BackendError> {
        let path = self.fs_path(id).join("cgroup.kill");
        fs::write(&path, "1").map_err(|e| BackendError::from_io(id, "kill", e))
    }

    fn is_populated(&self, id: &ScopeId) -> Result<bool, BackendError> {
        Self::read_populated(&self.fs_path(id))
            .map_err(|e| BackendError::from_io(id, "is_populated", e))
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
        assert!(b.exists(&id).unwrap());
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
        assert!(!b.exists(&id).unwrap());
    }

    #[test]
    fn read_populated_parses_cgroup_events() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        b.create(&id).unwrap();
        let path = b.fs_path(&id);
        fs::write(path.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        assert!(!b.is_populated(&id).unwrap());
        fs::write(path.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        assert!(b.is_populated(&id).unwrap());
    }

    #[test]
    fn members_parses_cgroup_procs() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        b.create(&id).unwrap();
        fs::write(b.fs_path(&id).join("cgroup.procs"), "123\n456\n").unwrap();
        let mut members = b.members(&id).unwrap();
        members.sort();
        assert_eq!(members, vec![123, 456]);
    }

    #[test]
    fn move_pid_writes_to_cgroup_procs() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        b.create(&id).unwrap();
        // Not a real cgroup.procs, so this is a plain file write -- but it
        // does exercise the same path and error-mapping move_pid uses.
        fs::write(b.fs_path(&id).join("cgroup.procs"), "").unwrap();
        b.move_pid(999, &id).unwrap();
        assert_eq!(b.members(&id).unwrap(), vec![999]);
    }

    #[test]
    fn move_pid_into_missing_scope_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend(&tmp);
        let id = ScopeId::parse("user/1000/sandbox").unwrap();
        match b.move_pid(1, &id) {
            Err(BackendError::NotFound(got)) => assert_eq!(got, id),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
