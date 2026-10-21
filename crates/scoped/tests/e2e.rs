//! End-to-end tests against a real cgroup v2 filesystem and a real D-Bus
//! daemon: root-only policy, tracked/untracked moves, exact pidfd target
//! termination, frozen whole-scope termination and whole-scope kill,
//! target/scope lifecycle signals, and restart reconstruction exercised
//! through the actual `scoped` binary,
//! not the library-level fakes the
//! unit tests elsewhere in this crate use.
//!
//! Each case is hermetic: it spawns its own `dbus-daemon` on a private
//! socket and gives `scoped` its own `--scope-root` directly under the
//! cgroup2 mount. Nothing touches the real system bus, so these tests
//! neither need `dist/dbus/org.decoupling.scoped1.conf` installed nor
//! disturb a `scoped` already running on the machine.
//!
//! Requires root (creating/moving/killing real cgroups, and the
//! root-only caller checks), a cgroup2 mount at
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

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};

#[zbus::proxy(
    interface = "org.decoupling.scoped1.Manager",
    default_service = "org.decoupling.scoped1",
    default_path = "/org/decoupling/scoped1"
)]
trait Manager {
    async fn create(&self, id: &str) -> zbus::Result<()>;

    #[zbus(name = "Move")]
    async fn move_pid(&self, pid: u32, id: &str, target_id: &str) -> zbus::Result<()>;

    async fn scope_of(&self, pid: u32) -> zbus::Result<String>;

    async fn list(&self, prefix: &str) -> zbus::Result<Vec<String>>;

    async fn target_exists(&self, id: &str, target_id: &str) -> zbus::Result<bool>;

    async fn scope_populated(&self, id: &str) -> zbus::Result<bool>;

    async fn terminate_target(&self, id: &str, target_id: &str) -> zbus::Result<()>;

    async fn kill_target(&self, id: &str, target_id: &str) -> zbus::Result<()>;

    async fn terminate_scope(&self, id: &str) -> zbus::Result<()>;

    async fn kill_scope(&self, id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn target_gone(&self, id: String, target_id: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn scope_empty(&self, id: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn scope_removed(&self, id: String) -> zbus::Result<()>;
}

const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;
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

fn process_cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read process stat");
    let fields = stat
        .rsplit_once(") ")
        .expect("process stat has a command terminator")
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let user = fields[11].parse::<u64>().expect("parse process user ticks");
    let system = fields[12]
        .parse::<u64>()
        .expect("parse process system ticks");
    user + system
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

    /// Takes the bus down under the daemons connected to it.
    fn stop(&self) {
        let _ = nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGTERM);
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

    /// Waits for `scoped` to exit on its own, returning its status, or
    /// `None` on timeout.
    fn wait_for_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
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
fn synchronized_scope_watchers_block_without_spinning() {
    require_root();
    let _wd = Watchdog::start(
        "synchronized_scope_watchers_block_without_spinning",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));
    let scoped_pid = scoped.child.id();

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;
        let mut members = Vec::new();
        let mut ids = Vec::new();
        for _ in 0..4 {
            let id = format!("sessiond/user/0/session/{}", unique("cpu"));
            proxy.create(&id).await.expect("Create");
            let member = Member::spawn(&["sleep", "300"]);
            proxy
                .move_pid(member.pid(), &id, "manager")
                .await
                .expect("tracked Move");
            ids.push(id);
            members.push(member);
        }

        // Establishing the baseline by reading this exact open file must make
        // a subsequent POLLPRI wait block until the requested timeout.
        let events_path = scoped.scope_path(&ids[0]).join("cgroup.events");
        let mut events = File::open(&events_path).expect("open cgroup.events");
        events.seek(SeekFrom::Start(0)).unwrap();
        let mut content = String::new();
        events.read_to_string(&mut content).unwrap();
        assert!(content.lines().any(|line| line == "populated 1"));
        let mut fds = [PollFd::new(events.as_fd(), PollFlags::POLLPRI)];
        let started = Instant::now();
        assert_eq!(poll(&mut fds, PollTimeout::from(250u16)).unwrap(), 0);
        assert!(started.elapsed() >= Duration::from_millis(200));

        // Four unsynchronized watcher fds previously consumed about four CPU
        // cores. Allow a generous scheduler/debug-build margin while still
        // making that regression unmistakable.
        let before = process_cpu_ticks(scoped_pid);
        std::thread::sleep(Duration::from_millis(1500));
        let delta = process_cpu_ticks(scoped_pid) - before;
        assert!(delta <= 20, "idle scoped consumed {delta} CPU ticks");

        drop(members);
    });
}

#[test]
#[ignore]
fn tracked_target_exit_precedes_scope_drain() {
    require_root();
    let _wd = Watchdog::start(
        "tracked_target_exit_precedes_scope_drain",
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

        let mut manager = Member::spawn(&["sleep", "300"]);
        let mut leftover = Member::spawn(&["sleep", "300"]);
        proxy
            .move_pid(manager.pid(), &id, "manager")
            .await
            .expect("tracked Move");
        let collision = proxy
            .move_pid(leftover.pid(), &id, "manager")
            .await
            .expect_err("a live target ID must not be rebound");
        assert!(
            collision.to_string().contains("TargetAlreadyExists"),
            "unexpected collision error: {collision}"
        );
        proxy
            .move_pid(leftover.pid(), &id, "")
            .await
            .expect("untracked Move");

        assert_eq!(proxy.scope_of(manager.pid()).await.unwrap(), id);
        assert!(proxy.target_exists(&id, "manager").await.unwrap());
        assert!(proxy.scope_populated(&id).await.unwrap());
        assert!(proxy.list(prefix).await.unwrap().contains(&id));
        assert!(
            xattr::get(scoped.scope_path(&id), "user.scoped.target.manager")
                .unwrap()
                .is_some()
        );

        // Arm every stream before the operation, as sessiond will.
        let mut target_gone = proxy.receive_target_gone().await.unwrap();
        let mut empty = proxy.receive_scope_empty().await.unwrap();
        let mut removed = proxy.receive_scope_removed().await.unwrap();

        proxy
            .terminate_target(&id, "manager")
            .await
            .expect("TerminateTarget");
        let gone = target_gone.next().await.expect("TargetGone");
        let args = gone.args().unwrap();
        assert_eq!(args.id, id);
        assert_eq!(args.target_id, "manager");
        assert_eq!(
            manager
                .wait_for_exit(Duration::from_secs(5))
                .expect("manager exits")
                .signal(),
            Some(SIGTERM)
        );

        // Target death is not scope emptiness: the untracked child remains.
        assert!(!proxy.target_exists(&id, "manager").await.unwrap());
        assert!(proxy.scope_populated(&id).await.unwrap());
        assert!(leftover.wait_for_exit(Duration::from_millis(100)).is_none());

        proxy.kill_scope(&id).await.expect("KillScope");
        assert_eq!(empty.next().await.unwrap().args().unwrap().id, id);
        assert_eq!(removed.next().await.unwrap().args().unwrap().id, id);
        assert_eq!(
            leftover
                .wait_for_exit(Duration::from_secs(5))
                .expect("leftover killed")
                .signal(),
            Some(SIGKILL)
        );
        assert!(!proxy.scope_populated(&id).await.unwrap());
        assert!(!scoped.scope_path(&id).exists());
        proxy
            .kill_scope(&id)
            .await
            .expect("KillScope is idempotent after removal");
    });
}

#[test]
#[ignore]
fn terminate_scope_signals_descendants_and_always_thaws() {
    require_root();
    let _wd = Watchdog::start(
        "terminate_scope_signals_descendants_and_always_thaws",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;
        let parent = format!("sessiond/user/0/session/{}", unique("parent"));
        let normal_scope = format!("{parent}/normal");
        let stubborn_scope = format!("{parent}/stubborn");
        proxy.create(&normal_scope).await.unwrap();
        proxy.create(&stubborn_scope).await.unwrap();

        let mut normal = Member::spawn(&["sleep", "300"]);
        let mut stubborn = Member::spawn(&["sh", "-c", "trap '' TERM; exec sleep 300"]);
        proxy
            .move_pid(normal.pid(), &normal_scope, "")
            .await
            .unwrap();
        proxy
            .move_pid(stubborn.pid(), &stubborn_scope, "")
            .await
            .unwrap();

        proxy
            .terminate_scope(&parent)
            .await
            .expect("TerminateScope");
        assert_eq!(
            std::fs::read_to_string(scoped.scope_path(&parent).join("cgroup.freeze"))
                .unwrap()
                .trim(),
            "0",
            "TerminateScope must thaw before replying"
        );
        assert_eq!(
            normal
                .wait_for_exit(Duration::from_secs(5))
                .expect("normal member handles SIGTERM")
                .signal(),
            Some(SIGTERM)
        );
        assert!(
            stubborn.wait_for_exit(Duration::from_millis(200)).is_none(),
            "SIGTERM-ignoring member should remain for escalation"
        );

        proxy
            .kill_scope(&parent)
            .await
            .expect("KillScope escalation");
        assert_eq!(
            stubborn
                .wait_for_exit(Duration::from_secs(5))
                .expect("stubborn member killed")
                .signal(),
            Some(SIGKILL)
        );
        proxy
            .terminate_scope(&parent)
            .await
            .expect("TerminateScope is idempotent after removal");
    });
}

#[test]
#[ignore]
fn kill_target_is_exact_and_forceful() {
    require_root();
    let _wd = Watchdog::start("kill_target_is_exact_and_forceful", Duration::from_secs(60));
    let bus = TestBus::start();
    let scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;
        let id = format!("sessiond/user/0/session/{}", unique("sess"));
        proxy.create(&id).await.unwrap();

        let mut manager = Member::spawn(&["sh", "-c", "trap '' TERM; sleep 300"]);
        let mut leftover = Member::spawn(&["sleep", "300"]);
        proxy.move_pid(manager.pid(), &id, "manager").await.unwrap();
        proxy.move_pid(leftover.pid(), &id, "").await.unwrap();

        proxy.terminate_target(&id, "manager").await.unwrap();
        assert!(manager.wait_for_exit(Duration::from_secs(2)).is_none());

        let mut gone = proxy.receive_target_gone().await.unwrap();
        proxy.kill_target(&id, "manager").await.unwrap();
        assert_eq!(
            gone.next().await.unwrap().args().unwrap().target_id,
            "manager"
        );
        assert_eq!(
            manager
                .wait_for_exit(Duration::from_secs(5))
                .expect("target killed")
                .signal(),
            Some(SIGKILL)
        );
        assert!(leftover.wait_for_exit(Duration::from_millis(100)).is_none());
        assert!(proxy.scope_populated(&id).await.unwrap());

        let mut removed = proxy.receive_scope_removed().await.unwrap();
        proxy.kill_scope(&id).await.unwrap();
        removed.next().await.expect("ScopeRemoved");
        assert_eq!(
            leftover
                .wait_for_exit(Duration::from_secs(5))
                .expect("scope killed")
                .signal(),
            Some(SIGKILL)
        );
        assert!(!scoped.scope_path(&id).exists());
    });
}

#[test]
#[ignore]
fn moving_a_target_out_emits_target_gone() {
    require_root();
    let _wd = Watchdog::start(
        "moving_a_target_out_emits_target_gone",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;
        let from = format!("sessiond/user/0/session/{}", unique("from"));
        let to = format!("sessiond/user/0/session/{}", unique("to"));
        proxy.create(&from).await.unwrap();
        proxy.create(&to).await.unwrap();
        let mut member = Member::spawn(&["sleep", "300"]);
        proxy.move_pid(member.pid(), &from, "main").await.unwrap();

        let mut gone = proxy.receive_target_gone().await.unwrap();
        proxy
            .move_pid(member.pid(), &to, "replacement")
            .await
            .unwrap();
        assert!(!proxy.target_exists(&from, "main").await.unwrap());
        assert!(proxy.target_exists(&to, "replacement").await.unwrap());

        let signal = gone.next().await.expect("old target should become gone");
        let args = signal.args().unwrap();
        assert_eq!(args.id, from);
        assert_eq!(args.target_id, "main");

        proxy.kill_scope(&to).await.unwrap();
        assert_eq!(
            member
                .wait_for_exit(Duration::from_secs(5))
                .expect("member killed")
                .signal(),
            Some(SIGKILL)
        );
        assert!(!scoped.scope_path(&from).exists());
    });
}

#[test]
#[ignore]
fn every_unprivileged_caller_is_denied() {
    require_root();
    let _wd = Watchdog::start(
        "every_unprivileged_caller_is_denied",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        wait_for_manager(&connection).await;
    });

    // The private bus routes this call; scoped itself must reject it.
    for id in [
        "sessiond/user/0/session/denied",
        &format!("user/{NOBODY}/also-denied"),
    ] {
        let (ok, stderr) = busctl_call_as(&bus, NOBODY, &["Create", "s", id]);
        assert!(!ok, "non-root Create unexpectedly succeeded");
        assert!(
            stderr.contains("Access denied")
                || stderr.contains("AccessDenied")
                || stderr.contains("root-only"),
            "expected root-only AccessDenied, got: {stderr}"
        );
        assert!(!scoped.scope_path(id).exists());
    }
}

#[test]
#[ignore]
fn restart_recovers_targets_and_scope_watchers() {
    require_root();
    let _wd = Watchdog::start(
        "restart_recovers_targets_and_scope_watchers",
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
        proxy.create(&populated_id).await.unwrap();
        let member = Member::spawn(&["sleep", "300"]);
        proxy
            .move_pid(member.pid(), &populated_id, "manager")
            .await
            .unwrap();
        proxy.create(&empty_id).await.unwrap();
        member
    });

    scoped.crash();
    assert!(scoped.scope_path(&populated_id).is_dir());
    assert!(scoped.scope_path(&empty_id).is_dir());
    let scoped_b = ScopedProcess::spawn(&bus, &scope_root);

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;
        assert!(!scoped_b.scope_path(&empty_id).exists());
        assert!(scoped_b.scope_path(&populated_id).is_dir());
        assert!(proxy.target_exists(&populated_id, "manager").await.unwrap());

        let mut gone = proxy.receive_target_gone().await.unwrap();
        let mut empty = proxy.receive_scope_empty().await.unwrap();
        let mut removed = proxy.receive_scope_removed().await.unwrap();
        member.0.kill().unwrap();
        member.0.wait().unwrap();

        let gone_signal = gone.next().await.unwrap();
        let args = gone_signal.args().unwrap();
        assert_eq!(args.id, populated_id);
        assert_eq!(args.target_id, "manager");
        assert_eq!(empty.next().await.unwrap().args().unwrap().id, populated_id);
        assert_eq!(
            removed.next().await.unwrap().args().unwrap().id,
            populated_id
        );
        assert!(!scoped_b.scope_path(&populated_id).exists());
    });
}

/// A second instance must not be able to take the well-known name away
/// from the running one. zbus's default `RequestName` flags
/// (ALLOW_REPLACEMENT | REPLACE_EXISTING | DO_NOT_QUEUE) would do exactly
/// that, leaving the original alive but unreachable -- and, once the
/// usurper exits, the name unowned, because DO_NOT_QUEUE keeps the
/// original out of the queue too. A supervisor cannot see any of that, so
/// duplicates have to fail instead.
#[test]
#[ignore]
fn a_second_instance_refuses_to_steal_the_name() {
    require_root();
    let _wd = Watchdog::start(
        "a_second_instance_refuses_to_steal_the_name",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let _first = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        let proxy = wait_for_manager(&connection).await;
        let owner_before = zbus::fdo::DBusProxy::new(&connection)
            .await
            .unwrap()
            .get_name_owner("org.decoupling.scoped1".try_into().unwrap())
            .await
            .expect("the first instance owns the name");

        let mut second = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));
        let status = second
            .wait_for_exit(Duration::from_secs(10))
            .expect("the second instance should exit instead of stealing the name");
        assert!(
            !status.success(),
            "the second instance exited successfully: {status:?}"
        );

        // The original is still the owner and still serving.
        let owner_after = zbus::fdo::DBusProxy::new(&connection)
            .await
            .unwrap()
            .get_name_owner("org.decoupling.scoped1".try_into().unwrap())
            .await
            .expect("the name still has an owner");
        assert_eq!(owner_before, owner_after);
        proxy
            .list("sessiond/user")
            .await
            .expect("the first instance still answers");
    });
}

/// Losing the bus costs us the name, and a process that is alive but
/// nameless is invisible to the supervisor: every caller gets
/// `ServiceUnknown` forever. Exiting non-zero is what gets us restarted.
#[test]
#[ignore]
fn losing_the_bus_connection_exits_nonzero() {
    require_root();
    let _wd = Watchdog::start(
        "losing_the_bus_connection_exits_nonzero",
        Duration::from_secs(60),
    );
    let bus = TestBus::start();
    let mut scoped = ScopedProcess::spawn(&bus, &unique("scoped-e2e"));

    zbus::block_on(async {
        let connection = bus.connect().await;
        wait_for_manager(&connection).await;
    });

    bus.stop();
    let status = scoped
        .wait_for_exit(Duration::from_secs(10))
        .expect("scoped should exit when the bus goes away");
    assert!(
        !status.success(),
        "scoped exited successfully after losing the bus: {status:?}"
    );
}
