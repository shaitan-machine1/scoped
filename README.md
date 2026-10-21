# scoped

`scoped` is **M0** of the [decoupling-logind](../..) plan: a D-Bus service
that owns the cgroup v2 scope hierarchy, process membership, and
tracked process termination and graceful/forced whole-scope signalling -- and nothing else. It
knows nothing about seats, sessions, service managers, or compositors.

> Durable state lives entirely in the cgroup tree (including tracked-target
> xattrs), so `scoped` can restart freely.

## Layout

This repo is a two-crate Cargo workspace:

| Crate | What |
|---|---|
| [`crates/scope-id`](crates/scope-id) | Dependency-free library: portable `ScopeId`/`TargetId` parsing and the `sessiond/...`/`user/...` naming conventions. Pinned by git tag from other repos (e.g. `sessiond`). |
| [`crates/scoped`](crates/scoped) | The Linux `scoped` binary: D-Bus service, cgroup v2 backend, pidfd target watchers, and empty-scope GC. |

Plus [`dist/dbus/org.decoupling.scoped1.conf`](dist/dbus/org.decoupling.scoped1.conf),
the bus policy -- see [Installing](#installing).

Inside `crates/scoped/src`:

- `backend/` -- `CgroupBackend`, the cgroup v2 implementation, process
  identity/pidfd handling, and versioned target records in cgroup xattrs.
- `policy.rs` -- the root-only Phase 1 authorization rule.
- `service.rs` -- root-policy-enforcing core logic, independent of D-Bus and
  unit tested against a fake backend.
- `watch.rs` -- pidfd target watchers plus `cgroup.events` scope watchers;
  emits `TargetGone`/`ScopeEmpty`/`ScopeRemoved`, garbage-collects empty
  scopes, and reconstructs watchers from the cgroup tree on startup.
- `dbus.rs` -- the `org.decoupling.scoped1.Manager` interface: argument
  parsing, caller-uid resolution via the bus daemon, and error mapping.
- `config.rs` / `main.rs` -- CLI and wiring.

## Building and testing

```sh
cargo build --workspace
cargo test --workspace     # unit tests only; no root, no real cgroups
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

### End-to-end tests (need root)

`crates/scoped/tests/e2e.rs` drives the actual compiled binary against a
real cgroup v2 filesystem and a real D-Bus daemon: tracked and untracked
moves, `TargetExists`/`ScopePopulated`, exact pidfd termination and kill,
frozen whole-scope termination, whole-scope kill, root-only policy,
distinct target/scope lifecycle events,
and restart reconstruction of both cgroup and target watchers.

Each case is hermetic: it starts its own `dbus-daemon` on a private socket
and gets its own `--scope-root`, so the tests need no installed bus policy
and don't disturb a `scoped` already running on the machine. They need
root, a cgroup2 mount (`SCOPED_E2E_CGROUP_MOUNT` to override
`/sys/fs/cgroup`), and `dbus-daemon`/`busctl` on `PATH`.

They're `#[ignore]`d, so a plain `cargo test` never touches real cgroups:

```sh
sudo -E cargo test -p scoped --test e2e -- --ignored --test-threads=4

# If cargo isn't on root's PATH, use a fresh target directory so an old
# e2e executable can never be selected accidentally:
target=$(mktemp -d)
trap 'rm -rf "$target"' EXIT
CARGO_TARGET_DIR="$target" cargo test -p scoped --test e2e --no-run
test_binary=$(find "$target/debug/deps" -maxdepth 1 -type f -name 'e2e-*' -perm -111)
sudo "$test_binary" --ignored --test-threads=4
trap - EXIT
rm -rf "$target"
```

## Installing

The system bus denies owning any name by default (`<deny own="*"/>` in
`system.conf`), so the bus policy has to be installed or `scoped` will
fail at startup with `org.freedesktop.DBus.Error.AccessDenied: Request to
own name refused by policy`:

```sh
install -Dm644 dist/dbus/org.decoupling.scoped1.conf \
    /usr/share/dbus-1/system.d/org.decoupling.scoped1.conf
```

Phase 1 is root-only. The policy rejects non-root method traffic as defense
in depth, and `scoped` independently verifies the D-Bus caller UID on every
method.

## Running it by hand

```sh
# Production: system bus, real cgroup2 mount, default scope root
# (/sys/fs/cgroup/scoped). Needs root (or a delegated, writable subtree).
sudo scoped --bus system
```

`--bus session` remains available for a deliberately configured root-owned
test bus, but an ordinary user's session bus is not useful now that every
method is root-only. Both bus modes honor `DBUS_SYSTEM_BUS_ADDRESS` /
`DBUS_SESSION_BUS_ADDRESS`; the e2e suite uses that to supply private buses.

```sh
busctl --system call org.decoupling.scoped1 /org/decoupling/scoped1 \
  org.decoupling.scoped1.Manager Create s \
  "sessiond/user/1000/service"

# Third argument is a scope-local target ID; empty means untracked.
busctl --system call org.decoupling.scoped1 /org/decoupling/scoped1 \
  org.decoupling.scoped1.Manager Move uss 12345 \
  "sessiond/user/1000/service" "manager"
```

## D-Bus interface

`org.decoupling.scoped1.Manager` at `/org/decoupling/scoped1` on the
system bus (well-known name `org.decoupling.scoped1`):

| Member | Signature | Notes |
|---|---|---|
| `Create(id)` | `s` -> `()` | Atomic; `ScopeAlreadyExists` if `id` already exists. |
| `Move(pid, id, target)` | `uss` -> `()` | Moves and optionally registers one exact process instance. Empty `target` means untracked. |
| `ScopeOf(pid)` | `u` -> `s` | Empty string if `pid` isn't in any managed scope. |
| `List(prefix)` | `s` -> `as` | Descendants excluding `prefix`; missing prefix gives an empty list. |
| `TargetExists(id, target)` | `ss` -> `b` | Validates stored identity and exact scope membership; missing target/scope is false. |
| `ScopePopulated(id)` | `s` -> `b` | Includes descendants; empty or missing scope is false. |
| `TerminateTarget(id, target)` | `ss` -> `()` | SIGTERM to the exact process through pidfd. |
| `KillTarget(id, target)` | `ss` -> `()` | SIGKILL to the exact process through pidfd. |
| `TerminateScope(id)` | `s` -> `()` | Freezes the subtree, queues SIGTERM through pidfds for every current member, then unconditionally thaws; missing scope is success. |
| `KillScope(id)` | `s` -> `()` | SIGKILLs the whole subtree via `cgroup.kill`; missing scope is success. |
| `TargetGone(id, target)` | signal, `ss` | The binding no longer names a live process in that exact scope. |
| `ScopeEmpty(id)` | signal, `s` | A scope's population (including descendants) dropped to zero. |
| `ScopeRemoved(id)` | signal, `s` | `scoped` removed a scope's cgroup directory. |

Errors use the stable `org.decoupling.scoped1.Error.*` namespace:
`AccessDenied`, `InvalidScopeId`, `InvalidTargetId`, `ScopeNotFound`,
`ScopeAlreadyExists`, `ProcessNotFound`, `TargetAlreadyExists`,
`TargetNotFound`, `TargetGone`, and `BackendFailure`.

**Policy:** every method is root-only. The UID comes from bus credentials,
never request data. The D-Bus policy also blocks non-root calls.

## Design notes

- **Create/Move race, and why empty-scope GC doesn't eat it.** A scope is
  only auto-removed on a genuine `populated: 1 -> 0` transition, never on
  "still 0 since creation". So `Create` followed by `Move` is safe.
- **Tracked moves are one operation.** A non-empty target ID is recorded as
  a pending xattr, the process is moved, identity and exact membership are
  revalidated, and the record is activated before reply. `exec` preserves
  the binding. Target IDs are caller-chosen and scope-local.
- **Restart-safe target identity.** Xattrs persist `(PID, start time)`, not
  pidfds. Startup reopens pidfds only after checking start time and scope
  membership; stale pending/active records are discarded.
- **Only leaf (`Create()`-d) scopes get a watcher thread.** Intermediate
  directories (e.g. `sessiond/user/1000/session`, auto-`mkdir -p`'d) never
  have members of their own -- their emptiness is entirely a function of
  their descendants -- so they're cleaned up by the upward cascade after a
  leaf is removed, not by their own watcher.
- **Restart safety.** On startup, before serving any request, `scoped`
  sweeps the whole managed tree bottom-up, removing already-empty leaves
  (cascading into ancestors), and starts a watcher for every leaf that's
  still populated. See the "Accepted limitations" note below for the one
  case this can't distinguish.
- **Target vs. scope lifecycle.** pidfd readiness emits `TargetGone` for one
  registered process. `cgroup.events` emits `ScopeEmpty`; the existing
  watcher then removes the directory and emits `ScopeRemoved`. Each scope
  watcher rewinds and reads the exact `cgroup.events` fd it polls, synchronizing
  kernfs's per-open event counter so an unchanged scope blocks instead of
  repeatedly reporting `POLLPRI|POLLERR`.
- **Subscribe, then query.** D-Bus signals are not durable. Consumers arm
  target and scope streams first, then call `TargetExists` and
  `ScopePopulated` before initiating teardown.
- **First owner wins, and losing the bus is fatal.** The name is requested
  with `DO_NOT_QUEUE` alone, *not* zbus's default
  `ALLOW_REPLACEMENT | REPLACE_EXISTING | DO_NOT_QUEUE`: with the defaults
  any second instance silently steals `org.decoupling.scoped1` from the
  running daemon, which keeps running unreachable, and once the usurper
  exits the name is left unowned (`DO_NOT_QUEUE` keeps the original out of
  the queue as well). A duplicate therefore fails to start, and if the
  connection is ever lost `scoped` exits non-zero so the supervisor
  restarts it -- an alive-but-nameless daemon looks healthy to the
  supervisor while every caller gets `ServiceUnknown`.

### Known limitations

- **Numeric migration remains non-atomic.** Linux `cgroup.procs` accepts a
  PID, not a pidfd. `Move` pins the process first and validates identity and
  membership afterwards, so a durable target never binds a recycled PID,
  but the kernel write itself still has a tiny PID-reuse correctness race.
  Phase 1 is root-only, so this is not an unprivileged escalation path;
  callers also keep the process blocked/alive until the reply.
- **A `Create()`-d scope that never gets a member is never collected**
  until the next restart, since the GC only fires on a real 1 -> 0
  transition. A client that calls `Create` and then dies leaks an empty
  directory.
- **The restart sweep can't tell a pending scope from garbage.** A scope
  `Create()`-d right before a crash, with its `Move()` not yet landed,
  looks exactly like stale leftovers on disk: an empty leaf directory. The
  sweep removes both, so the caller that was about to `Move()` into it
  gets `ScopeNotFound` instead of succeeding.
- **No resource control.** `scoped` never writes `cgroup.subtree_control`,
  so no controllers are enabled on the scopes it makes. That's what keeps
  the "no internal processes" rule from biting (a scope may hold both
  processes and child scopes), but it also means scopes can't carry limits
  yet.
- **Host cgroup namespace assumed.** `ScopeOf` maps `/proc/<pid>/cgroup`
  back to a scope id by prefix. Those paths are relative to the *reader's*
  cgroup namespace, so `scoped` and the processes it manages have to share
  one -- true for a normal, non-containerized deployment.
- **No graceful shutdown yet.** SIGTERM/SIGINT aren't handled; `scoped`
  keeps no state outside the cgroup tree, so it's restart-safe regardless,
  but the watcher threads are simply torn down with the process.
