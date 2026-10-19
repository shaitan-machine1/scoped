//! End-to-end tests against a real cgroup v2 filesystem and a real D-Bus
//! daemon: `M0`'s acceptance criteria ("create, move, terminate, kill and
//! the empty event work; policy enforced; survives a restart") exercised
//! through the actual `scoped` binary, not the library-level fakes the
//! unit tests elsewhere in this crate use.
//!
//! Each case is hermetic: it spawns its own `dbus-daemon` on a private
//! socket and gives `scoped` its own `--scope-root` directly under the
//! cgroup2 mount. Nothing touches the real system bus, so these tests
//! neither need `dist/dbus/org.decoupling.scoped1.conf` installed nor
//! disturb a `scoped` already running on the machine.
//!
//! Requires root (creating/moving/killing real cgroups, and the
//! process-ownership checks that depend on real uids), a cgroup2 mount at
//! `/sys/fs/cgroup` (override with `SCOPED_E2E_CGROUP_MOUNT`), and
//! `dbus-daemon` on `PATH`.
//!
//! Every test is `#[ignore]`d so a plain `cargo test` never touches real
//! cgroups. Run them with:
//!
//! ```text
//! cargo build && sudo -E ./target/debug/deps/e2e-* --ignored --test-threads=4
//! # or, if cargo itself is available to root:
//! sudo -E cargo test -p scoped --test e2e -- --ignored
//! ```

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;

#[zbus::proxy(
    interface = "org.decoupling.scoped1.Manager",
    default_service = "org.decoupling.scoped1",
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
/// The uid the policy tests make their "unprivileged caller" calls as.
const NOBODY: u32 = 65534;

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

/// Removes a cgroup directory tree bottom-up.
///
/// Deliberately *not* `std::fs::remove_dir_all`: on cgroupfs the control
/// files inside a directory can't be unlinked, so `remove_dir_all` fails
/// outright. Only the directories themselves are removable, and only once
/// they hold no processes.
fn rmdir_tree(path: &Path) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            rmdir_tree(&entry.path());
        }
    }
    let _ = std::fs::remove_dir(path);
}

/// A coarse, independent-OS-thread safety net: if not disarmed (dropped)
/// within `timeout`, aborts the whole test process with a clear message.
///
/// Signal streams are awaited directly inside `zbus::block_on`, as in
/// zbus's own signal-receiving examples -- deliberately *not* polled by
/// hand with sleeps in between, which risks starving the work the
/// connection has to do to deliver a message. A hung `.await` is a real
/// bug worth seeing loudly, so this aborts rather than quietly truncating
/// a stream.
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

/// A `sleep`-like child that gets killed when the test drops it, so a
/// failing assertion can't leave strays behind.
struct Member(Child);

impl Member {
    fn spawn(args: &[&str]) -> Self {
        let child = Command::new(args[0])
            .args(&args[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {args:?}: {e}"));
        Member(child)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }

    /// Waits for the process to exit, returning its status, or `None` on
    /// timeout.
    fn wait_for_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.0.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                Err(e) => panic!("try_wait failed: {e}"),
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A private `dbus-daemon` for one test: its own socket, and a policy that
/// (unlike the real system bus) lets anyone own names and send method
/// calls. That keeps the tests hermetic and lets the policy cases prove
/// that it is *`scoped`* rejecting an unprivileged caller, rather than the
/// bus's own `send_destination` rules.
struct TestBus {
    dir: tempfile::TempDir,
    pid: nix::unistd::Pid,
    address: String,
}

impl TestBus {
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("make tempdir for the test bus");
        // The unprivileged callers in the policy tests have to be able to
        // traverse to the socket.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod the test bus dir");

        let socket = dir.path().join("bus");
        let config_path = dir.path().join("bus.conf");
        let config = format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path={socket}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <!-- All four message types in both directions. Forgetting to allow
         *sending* method_return/error is a great way to spend an hour
         debugging a service that looks hung but is actually replying
         into a wall. -->
    <allow send_type="method_call"/>
    <allow send_type="method_return"/>
    <allow send_type="error"/>
    <allow send_type="signal"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
  </policy>
</busconfig>
"#,
            socket = socket.display()
        );
        let mut f = std::fs::File::create(&config_path).expect("write the test bus config");
        f.write_all(config.as_bytes()).expect("write the config");
        drop(f);

        let out = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config_path.display()))
            .arg("--fork")
            .arg("--print-pid")
            .output()
            .expect("spawn dbus-daemon (is it installed?)");
        assert!(
            out.status.success(),
            "dbus-daemon failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let pid: i32 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("dbus-daemon --print-pid should print a pid");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "test bus socket never appeared");
            std::thread::sleep(Duration::from_millis(20));
        }

        TestBus {
            dir,
            pid: nix::unistd::Pid::from_raw(pid),
            address: format!("unix:path={}", socket.display()),
        }
    }

    fn address(&self) -> &str {
        &self.address
    }

    async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address())
            .build()
            .await
            .expect("connect to the test bus")
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGTERM);
        let _ = &self.dir;
    }
}

/// A running `scoped`, pointed at a test bus and its own cgroup subtree.
struct ScopedProcess {
    child: Child,
    scope_root: String,
}

impl ScopedProcess {
    fn spawn(bus: &TestBus, scope_root: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_scoped"))
            .args([
                "--cgroup-mount",
                cgroup_mount().to_str().unwrap(),
                "--scope-root",
                scope_root,
                "--bus",
                "system",
            ])
            .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn the scoped binary");
        ScopedProcess {
            child,
            scope_root: scope_root.to_string(),
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

    /// SIGKILLs `scoped` itself, simulating a crash: the cgroup tree is
    /// left exactly as it was, nothing is cleaned up.
    fn crash(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ScopedProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        rmdir_tree(&self.base_path());
    }
}

/// Waits for `scoped` to take its well-known name on `connection`, then
/// returns a proxy to it.
async fn wait_for_manager(connection: &zbus::Connection) -> ManagerProxy<'static> {
    let dbus = zbus::fdo::DBusProxy::new(connection)
        .await
        .expect("build org.freedesktop.DBus proxy");
    let name = zbus::names::BusName::try_from("org.decoupling.scoped1").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if dbus.name_has_owner(name.clone()).await.unwrap_or(false) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "scoped never took org.decoupling.scoped1 on the test bus"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    ManagerProxy::new(connection)
        .await
        .expect("build ManagerProxy")
}

/// Runs `busctl call ...` against the test bus as `uid`, returning
/// (success, stderr).
fn busctl_call_as(bus: &TestBus, uid: u32, args: &[&str]) -> (bool, String) {
    let out = Command::new("busctl")
        .arg(format!("--address={}", bus.address()))
        .arg("call")
        .arg("org.decoupling.scoped1")
        .arg("/org/decoupling/scoped1")
        .arg("org.decoupling.scoped1.Manager")
        .args(args)
        .uid(uid)
        .gid(uid)
        // busctl inherits root's HOME otherwise, which an unprivileged uid
        // can't read.
        .env("HOME", "/tmp")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run busctl (is it installed?)");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
#[ignore]
fn create_move_list_scope_of_and_graceful_terminate() {
    require_root();
    let _wd = Watchdog::start(
        "create_move_list_scope_of_and_graceful_terminate",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;

        let prefix = "sessiond/user/0/session";
        let id = format!("{prefix}/{}", unique("sess"));

        proxy.create(&id).await.expect("Create");
        assert!(
            scoped.scope_path(&id).is_dir(),
            "scope directory should exist after Create"
        );

        // Exits cleanly on SIGTERM.
        let mut member = Member::spawn(&["sleep", "300"]);
        let pid = member.pid();

        proxy.move_pid(pid, &id).await.expect("Move");
        assert_eq!(proxy.scope_of(pid).await.expect("ScopeOf"), id);

        let listed = proxy.list(prefix).await.expect("List");
        assert!(listed.contains(&id), "List({prefix}) should include {id}");
        assert!(
            !listed.contains(&prefix.to_string()),
            "List must not include the prefix itself, got {listed:?}"
        );

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
        let status = member
            .wait_for_exit(Duration::from_secs(5))
            .expect("SIGTERM'd member should have exited");
        assert_eq!(
            status.signal(),
            Some(SIGTERM),
            "member should have died to SIGTERM, not something else"
        );

        // The now-childless ancestors should have been cascaded away too,
        // right up to (but not including) the managed root.
        assert!(
            !scoped.scope_path(prefix).exists(),
            "empty ancestor directories should be cascaded away"
        );
        assert!(
            scoped.base_path().is_dir(),
            "the managed root itself must survive"
        );
    });
}

#[test]
#[ignore]
fn kill_is_forceful_even_against_a_sigterm_trap() {
    require_root();
    let _wd = Watchdog::start(
        "kill_is_forceful_even_against_a_sigterm_trap",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;

        let id = format!("sessiond/user/0/session/{}", unique("sess"));
        proxy.create(&id).await.expect("Create");

        // Ignores SIGTERM; only SIGKILL (via cgroup.kill) can end it.
        let mut member = Member::spawn(&["sh", "-c", "trap '' TERM; sleep 300"]);
        proxy.move_pid(member.pid(), &id).await.expect("Move");

        // Prove the trap works: a graceful Terminate must leave it running.
        proxy.terminate(&id, SIGTERM).await.expect("Terminate");
        assert!(
            member.wait_for_exit(Duration::from_secs(2)).is_none(),
            "the SIGTERM-trapping member was supposed to survive Terminate"
        );
        assert!(
            scoped.scope_path(&id).is_dir(),
            "scope should still exist while a member survives"
        );

        let mut removed = proxy
            .receive_scope_removed()
            .await
            .expect("receive_scope_removed");

        proxy.kill(&id).await.expect("Kill");

        removed.next().await.expect("ScopeRemoved stream ended");

        let status = member
            .wait_for_exit(Duration::from_secs(5))
            .expect("Kill should have ended the member");
        assert_eq!(
            status.signal(),
            Some(9),
            "Kill should SIGKILL regardless of the member's SIGTERM trap"
        );
        assert!(!scoped.scope_path(&id).exists());
    });
}

#[test]
#[ignore]
fn an_unprivileged_caller_is_confined_to_its_own_namespace() {
    require_root();
    let _wd = Watchdog::start(
        "an_unprivileged_caller_is_confined_to_its_own_namespace",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        wait_for_manager(&connection).await;
    });

    // Denied: the sessiond/ namespace is root-only.
    let forbidden = "sessiond/user/0/session/should-be-denied";
    let (ok, stderr) = busctl_call_as(&bus, NOBODY, &["Create", "s", forbidden]);
    assert!(
        !ok,
        "an unprivileged caller must not create a sessiond scope"
    );
    assert!(
        stderr.contains("Access denied") || stderr.contains("AccessDenied"),
        "expected an AccessDenied error, got: {stderr}"
    );
    assert!(
        !scoped.scope_path(forbidden).exists(),
        "the denied scope must not have been created"
    );

    // Denied: another uid's namespace.
    let other = "user/1234/not-mine";
    let (ok, stderr) = busctl_call_as(&bus, NOBODY, &["Create", "s", other]);
    assert!(
        !ok,
        "an unprivileged caller must not touch another uid's scopes"
    );
    assert!(
        stderr.contains("Access denied") || stderr.contains("AccessDenied"),
        "expected an AccessDenied error, got: {stderr}"
    );

    // Allowed: its own namespace. This is what proves the rejections above
    // came from scoped's uid policy and not from the bus refusing to route
    // the call at all.
    let own = format!("user/{NOBODY}/mine");
    let (ok, stderr) = busctl_call_as(&bus, NOBODY, &["Create", "s", &own]);
    assert!(
        ok,
        "an unprivileged caller may create its own scope: {stderr}"
    );
    assert!(scoped.scope_path(&own).is_dir());

    // Denied: moving a process it does not own (pid 1 is root's).
    let (ok, stderr) = busctl_call_as(&bus, NOBODY, &["Move", "us", "1", &own]);
    assert!(
        !ok,
        "an unprivileged caller must not move a process it doesn't own"
    );
    assert!(
        stderr.contains("Access denied") || stderr.contains("AccessDenied"),
        "expected an AccessDenied error, got: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(scoped.scope_path(&own).join("cgroup.procs"))
            .expect("read cgroup.procs")
            .trim(),
        "",
        "the denied Move must not have happened"
    );
}

#[test]
#[ignore]
fn restart_sweeps_never_populated_scopes_and_keeps_watching_populated_ones() {
    require_root();
    let _wd = Watchdog::start(
        "restart_sweeps_never_populated_scopes_and_keeps_watching_populated_ones",
        Duration::from_secs(90),
    );
    let bus = TestBus::start();
    let scope_root = unique("scoped-e2e-restart");
    let mut scoped = ScopedProcess::spawn(&bus, &scope_root);

    let populated_id = format!("sessiond/user/0/session/{}", unique("populated"));
    let empty_id = format!("sessiond/user/0/session/{}", unique("empty"));

    let mut member = zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;

        proxy.create(&populated_id).await.expect("Create populated");
        let member = Member::spawn(&["sleep", "300"]);
        proxy
            .move_pid(member.pid(), &populated_id)
            .await
            .expect("Move into populated");

        // Created, but nothing ever moved into it: on disk this is
        // indistinguishable from a scope whose Move() never landed before
        // a crash.
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

    // Restart against the same scope root.
    let scoped_b = ScopedProcess::spawn(&bus, &scope_root);

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;

        // The startup sweep runs to completion before the name is taken,
        // so by the time the proxy is usable the tree is already settled:
        // no sleep-and-hope here.
        assert!(
            !scoped_b.scope_path(&empty_id).exists(),
            "a never-populated scope must be swept on restart (accepted limitation)"
        );
        assert!(
            scoped_b.scope_path(&populated_id).is_dir(),
            "a populated scope must survive a restart"
        );

        // The watcher must have been re-established: killing the member
        // from outside the API still has to produce ScopeEmpty +
        // ScopeRemoved.
        let mut empty = proxy
            .receive_scope_empty()
            .await
            .expect("receive_scope_empty");
        let mut removed = proxy
            .receive_scope_removed()
            .await
            .expect("receive_scope_removed");

        drop(member.0.kill());
        let _ = member.0.wait();

        let empty_signal = empty
            .next()
            .await
            .expect("ScopeEmpty stream ended after restart");
        assert_eq!(empty_signal.args().unwrap().id, populated_id);

        let removed_signal = removed
            .next()
            .await
            .expect("ScopeRemoved stream ended after restart");
        assert_eq!(removed_signal.args().unwrap().id, populated_id);

        assert!(!scoped_b.scope_path(&populated_id).exists());
    });
}
