//! End-to-end tests against a real cgroup v2 filesystem and a real D-Bus
//! bus: `M0`'s acceptance criteria ("create, move, terminate, kill and the
//! empty event work; policy enforced; survives a restart") exercised
//! through the actual `scoped` binary, not the library-level fakes used by
//! the unit tests elsewhere in this crate.
//!
//! Requires:
//! - root (creating/moving/killing real cgroups, and the process-ownership
//!   checks that depend on real uids),
//! - a cgroup2 mount at `/sys/fs/cgroup` (or override via `SCOPED_E2E_CGROUP_MOUNT`),
//! - a reachable D-Bus system bus that lets root own arbitrary names
//!   (the default `system.conf` policy on every mainstream distro).
//!
//! Every test is `#[ignore]`d so a plain `cargo test` never touches real
//! cgroups. Run them with:
//!
//! ```text
//! sudo -E cargo test -p scoped --test e2e -- --ignored --test-threads=4
//! ```
//!
//! (`-E` to keep `CARGO_*`/`DBUS_SYSTEM_BUS_ADDRESS` etc.; `--test-threads`
//! can be raised since each test spawns its own `scoped` under an isolated
//! bus name and scope root.)

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use zbus::Connection;

#[zbus::proxy(
    interface = "org.decoupling.scoped1.Manager",
    default_path = "/org/decoupling/scoped1"
)]
trait Manager {
    async fn create(&self, id: &str) -> zbus::Result<()>;

    #[zbus(name = "Move")]
    async fn move_pid(&self, pid: u32, id: &str) -> zbus::Result<()>;

    async fn scope_of(&self, pid: u32) -> zbus::Result<String>;

    async fn list(&self, prefix: &str) -> zbus::Result<Vec<String>>;

    async fn terminate(&self, id: &str, signal: i32) -> zbus::Result<()>;

    async fn kill(&self, id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn scope_empty(&self, id: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn scope_removed(&self, id: String) -> zbus::Result<()>;
}

const SIGTERM: i32 = 15;

fn cgroup_mount() -> PathBuf {
    std::env::var("SCOPED_E2E_CGROUP_MOUNT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"))
}

fn require_root() {
    if !nix::unistd::Uid::effective().is_root() {
        panic!(
            "e2e tests touch real cgroups and must run as root; try:\n  \
             sudo -E cargo test -p scoped --test e2e -- --ignored"
        );
    }
}

fn unique(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{n}", std::process::id())
}

/// A running `scoped` child process, on its own bus name and cgroup
/// subtree so tests don't collide with each other.
struct ScopedProcess {
    child: Child,
    bus_name: String,
    scope_root: String,
}

impl ScopedProcess {
    fn spawn() -> Self {
        Self::spawn_with_scope_root(unique("scoped-e2e"))
    }

    /// Spawns a fresh `scoped` managing an *existing* `scope_root`
    /// directory tree, simulating a restart: same cgroups on disk, new
    /// process, new bus name (names are per-connection anyway).
    fn spawn_with_scope_root(scope_root: String) -> Self {
        let bus_name = format!("org.decoupling.scoped1.e2e.{}", unique("t"));
        let child = Command::new(env!("CARGO_BIN_EXE_scoped"))
            .args([
                "--cgroup-mount",
                cgroup_mount().to_str().unwrap(),
                "--scope-root",
                &scope_root,
                "--bus",
                "system",
                "--bus-name",
                &bus_name,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn the scoped binary");
        ScopedProcess {
            child,
            bus_name,
            scope_root,
        }
    }

    fn base_path(&self) -> PathBuf {
        cgroup_mount().join(&self.scope_root)
    }

    fn scope_path(&self, id: &str) -> PathBuf {
        let mut p = self.base_path();
        for seg in id.split('/') {
            p.push(seg);
        }
        p
    }

    /// Connects to the system bus and waits for this instance's bus name
    /// to appear, returning a ready-to-use proxy.
    async fn connect(&self) -> ManagerProxy<'static> {
        let connection = Connection::system()
            .await
            .expect("connect to the system bus");
        let dbus = zbus::fdo::DBusProxy::new(&connection)
            .await
            .expect("build org.freedesktop.DBus proxy");
        let name = zbus::names::BusName::try_from(self.bus_name.as_str()).expect("valid bus name");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if dbus.name_has_owner(name.clone()).await.unwrap_or(false) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "scoped did not appear on the bus as {} in time",
                self.bus_name
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        ManagerProxy::builder(&connection)
            .destination(self.bus_name.clone())
            .build()
            .await
            .expect("build ManagerProxy")
    }

    /// SIGKILLs the `scoped` process itself, simulating a crash: cgroups
    /// on disk are left exactly as they were, nothing is cleaned up.
    fn crash(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ScopedProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Best-effort: scoped normally cleans up after itself, but a
        // failing test may leave something behind.
        let _ = std::fs::remove_dir_all(self.base_path());
    }
}

/// A coarse, independent-OS-thread safety net: if not disarmed (dropped)
/// within `timeout`, aborts the whole test process with a clear message.
///
/// Signal streams are awaited directly inside `zbus::block_on`, exactly as
/// in zbus's own signal-receiving examples -- deliberately *not* polled by
/// hand with sleeps in between, since that could starve whatever
/// background work the connection needs to do to actually deliver a
/// message while this thread is sleeping instead of driving the executor.
/// A hung `.await` is a real bug worth seeing loudly, so this aborts
/// rather than silently truncating a stream.
struct Watchdog {
    done: std::sync::mpsc::Sender<()>,
}

impl Watchdog {
    fn start(label: &'static str, timeout: Duration) -> Self {
        let (done, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            if rx.recv_timeout(timeout).is_err() {
                eprintln!("e2e watchdog: {label} did not finish within {timeout:?}");
                std::process::abort();
            }
        });
        Watchdog { done }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        let _ = self.done.send(());
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore]
fn create_move_list_scope_of_and_graceful_terminate() {
    require_root();
    let scoped = ScopedProcess::spawn();
    let _wd = Watchdog::start(
        "create_move_list_scope_of_and_graceful_terminate",
        Duration::from_secs(30),
    );
    zbus::block_on(async {
        let proxy = scoped.connect().await;

        let prefix = "sessiond/user/0/session";
        let id = format!("{prefix}/{}", unique("sess"));

        proxy.create(&id).await.expect("Create");
        assert!(
            scoped.scope_path(&id).is_dir(),
            "scope directory should exist after Create"
        );

        // A process that exits cleanly on SIGTERM.
        let mut member = Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep");
        let pid = member.id();

        proxy.move_pid(pid, &id).await.expect("Move");
        assert_eq!(proxy.scope_of(pid).await.expect("ScopeOf"), id);

        let listed = proxy.list(prefix).await.expect("List");
        assert!(listed.contains(&id), "List({prefix}) should include {id}");

        let mut empty = proxy
            .receive_scope_empty()
            .await
            .expect("receive_scope_empty");
        let mut removed = proxy
            .receive_scope_removed()
            .await
            .expect("receive_scope_removed");

        proxy.terminate(&id, SIGTERM).await.expect("Terminate");

        let empty_signal = empty.next().await.expect("ScopeEmpty stream ended");
        assert_eq!(empty_signal.args().unwrap().id, id);

        let removed_signal = removed.next().await.expect("ScopeRemoved stream ended");
        assert_eq!(removed_signal.args().unwrap().id, id);

        assert!(
            !scoped.scope_path(&id).exists(),
            "scope directory should be gone after ScopeRemoved"
        );
        assert!(
            wait_for_exit(&mut member, Duration::from_secs(5)),
            "SIGTERM'd member should have exited"
        );
    });
}

#[test]
#[ignore]
fn kill_is_forceful_even_against_a_trap() {
    require_root();
    let scoped = ScopedProcess::spawn();
    let _wd = Watchdog::start(
        "kill_is_forceful_even_against_a_trap",
        Duration::from_secs(30),
    );
    zbus::block_on(async {
        let proxy = scoped.connect().await;
        let id = format!("sessiond/user/0/session/{}", unique("sess"));
        proxy.create(&id).await.expect("Create");

        // Ignores SIGTERM; only SIGKILL (via cgroup.kill) can end it.
        let mut member = Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 300"])
            .spawn()
            .expect("spawn sh");
        proxy.move_pid(member.id(), &id).await.expect("Move");

        let mut removed = proxy
            .receive_scope_removed()
            .await
            .expect("receive_scope_removed");

        proxy.kill(&id).await.expect("Kill");

        removed.next().await.expect("ScopeRemoved stream ended");

        assert!(
            wait_for_exit(&mut member, Duration::from_secs(5)),
            "Kill should SIGKILL the member regardless of its SIGTERM trap"
        );
        let status = member.wait().expect("wait");
        assert_eq!(
            status.signal(),
            Some(9),
            "member should have died to SIGKILL"
        );
    });
}

#[test]
#[ignore]
fn non_root_caller_is_denied() {
    require_root();
    let scoped = ScopedProcess::spawn();

    // busctl is the easiest way to make a call as a different uid from a
    // process we're already running as root; skip (don't fail) if it's not
    // installed, since that's an environment gap, not a scoped bug.
    if Command::new("busctl").arg("--version").output().is_err() {
        eprintln!("busctl not found, skipping non_root_caller_is_denied");
        return;
    }

    zbus::block_on(async {
        let _proxy = scoped.connect().await; // just to ensure the name is up
    });

    let id = "sessiond/user/0/session/should-be-denied";
    let status = Command::new("busctl")
        .args([
            "--system",
            "call",
            &scoped.bus_name,
            "/org/decoupling/scoped1",
            "org.decoupling.scoped1.Manager",
            "Create",
            "s",
            id,
        ])
        // Drop to an unprivileged, unrelated uid (nobody). We're root here,
        // so Command::uid is honored by the kernel at exec time.
        .uid(65534)
        .gid(65534)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run busctl");

    assert!(
        !status.status.success(),
        "a non-root caller must not be able to Create a sessiond/ scope"
    );
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert!(
        stderr.contains("AccessDenied") || stderr.contains("Access denied"),
        "expected an AccessDenied error, got: {stderr}"
    );
    assert!(
        !scoped.scope_path(id).exists(),
        "the denied scope must not have been created"
    );
}

#[test]
#[ignore]
fn restart_sweeps_never_populated_scopes_and_keeps_watching_populated_ones() {
    require_root();
    let _wd = Watchdog::start(
        "restart_sweeps_never_populated_scopes_and_keeps_watching_populated_ones",
        Duration::from_secs(45),
    );
    let scope_root = unique("scoped-e2e-restart");
    let mut scoped = ScopedProcess::spawn_with_scope_root(scope_root.clone());

    let populated_id = format!("sessiond/user/0/session/{}", unique("populated"));
    let empty_id = format!("sessiond/user/0/session/{}", unique("empty"));

    let mut member = zbus::block_on(async {
        let proxy = scoped.connect().await;

        proxy.create(&populated_id).await.expect("Create populated");
        let member = Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep");
        proxy
            .move_pid(member.id(), &populated_id)
            .await
            .expect("Move into populated");

        // Created, but nothing is ever moved into it: looks on disk
        // exactly like a scope whose Move() never landed before a crash.
        proxy.create(&empty_id).await.expect("Create empty");

        member
    });

    assert!(scoped.scope_path(&populated_id).is_dir());
    assert!(scoped.scope_path(&empty_id).is_dir());

    // Simulate a crash: no graceful shutdown, nothing cleaned up.
    scoped.crash();
    assert!(
        scoped.scope_path(&populated_id).is_dir(),
        "a crash must not touch the cgroup tree"
    );
    assert!(scoped.scope_path(&empty_id).is_dir());

    // Restart against the same scope_root.
    let scoped_b = ScopedProcess::spawn_with_scope_root(scope_root);

    zbus::block_on(async {
        let proxy = scoped_b.connect().await;

        // By the time the bus name is up, startup_scan has already run
        // (main.rs runs it before serving), so this should be immediate:
        // no sleep-and-hope.
        assert!(
            !scoped_b.scope_path(&empty_id).exists(),
            "a never-populated scope must be swept on restart (accepted limitation)"
        );
        assert!(
            scoped_b.scope_path(&populated_id).is_dir(),
            "a populated scope must survive a restart"
        );

        // The watcher for the populated scope must have been
        // re-established: killing its member from outside the API
        // (not via Terminate/Kill) should still produce ScopeEmpty +
        // ScopeRemoved.
        let mut empty = proxy
            .receive_scope_empty()
            .await
            .expect("receive_scope_empty");
        let mut removed = proxy
            .receive_scope_removed()
            .await
            .expect("receive_scope_removed");

        member.kill().expect("kill member directly");
        let _ = member.wait();

        let empty_signal = empty
            .next()
            .await
            .expect("ScopeEmpty stream ended after restart");
        assert_eq!(empty_signal.args().unwrap().id, populated_id);

        removed
            .next()
            .await
            .expect("ScopeRemoved stream ended after restart");

        assert!(!scoped_b.scope_path(&populated_id).exists());
    });
}
