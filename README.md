# scoped

`scoped` is **M0** of the [decoupling-logind](../..) plan: a D-Bus service
that owns the cgroup v2 scope hierarchy, process membership, and
termination/kill -- and nothing else. It knows nothing about seats,
sessions, or users beyond the bare `uid` a D-Bus caller connects with.

> State lives entirely in the cgroup tree, so `scoped` can restart freely.

## Layout

This repo is a two-crate Cargo workspace:

| Crate | What |
|---|---|
| [`crates/scope-id`](crates/scope-id) | Dependency-free library: scope ID parsing/validation, the `sessiond/...`/`user/...` naming conventions, and the "which caller may address which ID" policy rule. Pinned by git tag from other repos (e.g. `sessiond`). |
| [`crates/scoped`](crates/scoped) | The `scoped` binary: D-Bus service, cgroup v2 backend, empty-scope watcher/GC. |

Plus [`dist/dbus/org.decoupling.scoped1.conf`](dist/dbus/org.decoupling.scoped1.conf),
the bus policy -- see [Installing](#installing).

Inside `crates/scoped/src`:

- `backend/` -- `CgroupBackend` trait and `RealBackend`, the only code that
  touches `/sys/fs/cgroup`.
- `procfs.rs` -- process-uid lookups (`/proc/<pid>` ownership), used for
  "a non-root caller may only move processes it owns".
- `policy.rs` -- the caller-uid policy, combining `scope-id`'s namespace
  rule with process ownership.
- `service.rs` -- `Service<B: CgroupBackend>`: policy-enforcing
  `Create`/`Move`/`ScopeOf`/`List`/`Terminate`/`Kill`, independent of
  D-Bus. Unit tested against a fake backend.
- `watch.rs` -- background threads that watch `cgroup.events` for
  Create()-d scopes, emit `ScopeEmpty`/`ScopeRemoved`, garbage-collect
  empty scopes (cascading into now-empty ancestors), and rebuild this
  state from the tree on startup.
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
real cgroup v2 filesystem and a real D-Bus daemon: `Create`/`Move`/
`ScopeOf`/`List`, graceful `Terminate` vs. forceful `Kill`, an
unprivileged caller being confined to its own namespace, and restart
survival (a hard-killed `scoped`, restarted against the same cgroup
subtree, sweeps never-populated scopes and resumes watching populated
ones).

Each case is hermetic: it starts its own `dbus-daemon` on a private socket
and gets its own `--scope-root`, so the tests need no installed bus policy
and don't disturb a `scoped` already running on the machine. They need
root, a cgroup2 mount (`SCOPED_E2E_CGROUP_MOUNT` to override
`/sys/fs/cgroup`), and `dbus-daemon`/`busctl` on `PATH`.

They're `#[ignore]`d, so a plain `cargo test` never touches real cgroups:

```sh
sudo -E cargo test -p scoped --test e2e -- --ignored --test-threads=4

# If cargo isn't on root's PATH, build as yourself and run the test binary:
cargo test -p scoped --test e2e --no-run
sudo ./target/debug/deps/e2e-* --ignored --test-threads=4
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

That policy lets method calls through from any uid on purpose: `scoped`
does its own authorization from the caller's uid, which is what lets an
unprivileged caller manage its own `user/<uid>/...` scopes without a
bus-policy change per user.

## Running it by hand

```sh
# Production: system bus, real cgroup2 mount, default scope root
# (/sys/fs/cgroup/scoped). Needs root (or a delegated, writable subtree).
sudo scoped --bus system

# Against the session bus, for poking at it without a system-bus policy
# file. Still needs write access to whatever --cgroup-mount points at.
cargo run -p scoped -- --bus session --cgroup-mount /tmp/cgroup-test
```

Both honor `DBUS_SYSTEM_BUS_ADDRESS` / `DBUS_SESSION_BUS_ADDRESS`.

```sh
busctl --system call org.decoupling.scoped1 /org/decoupling/scoped1 \
  org.decoupling.scoped1.Manager Create s "user/1000/sandbox"

busctl --system call org.decoupling.scoped1 /org/decoupling/scoped1 \
  org.decoupling.scoped1.Manager Move us 12345 "user/1000/sandbox"
```

## D-Bus interface

`org.decoupling.scoped1.Manager` at `/org/decoupling/scoped1` on the
system bus (well-known name `org.decoupling.scoped1`, overridable with
`--bus-name` for running more than one instance side by side, e.g. in
tests):

| Member | Signature | Notes |
|---|---|---|
| `Create(id)` | `s` -> `()` | Atomic; `FileExists` if `id` already exists. |
| `Move(pid, id)` | `us` -> `()` | Non-root callers may only move processes they own. |
| `ScopeOf(pid)` | `u` -> `s` | Empty string if `pid` isn't in any managed scope. |
| `List(prefix)` | `s` -> `as` | Every descendant under `prefix`, not including `prefix` itself. A missing `prefix` gives an empty list, not an error. |
| `Terminate(id, signal)` | `si` -> `()` | Signals every process in `id` and its descendants; does not wait. |
| `Kill(id)` | `s` -> `()` | SIGKILLs the whole subtree via `cgroup.kill`. |
| `ScopeEmpty(id)` | signal, `s` | A scope's population (itself or any descendant) dropped to zero. |
| `ScopeRemoved(id)` | signal, `s` | `scoped` removed a scope's cgroup directory. |

**Policy** (from the caller's uid, resolved via the bus daemon, never from
the request body): root may address any scope id and move any process.
UID `N` may only address `user/N/...` ids, and may only move processes it
owns. The `sessiond/...` namespace is root-only.

## Design notes

- **Create/Move race, and why empty-scope GC doesn't eat it.** A scope is
  only auto-removed on a genuine `populated: 1 -> 0` transition, never on
  "still 0 since creation". So `Create(id)` immediately followed by
  `Move(pid, id)` is safe even though a brand new scope is, technically,
  momentarily empty.
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
- **`Terminate` vs `Kill`.** `Terminate` enumerates members (`id` and all
  descendants) and signals each individually -- racy by nature, matching
  the plan's "doesn't wait" semantics. `Kill` writes to `cgroup.kill`,
  which the kernel guarantees is atomic and recursive.

### Known limitations

- **Pid reuse (TOCTOU).** `Move` resolves a pid to an owner and then acts
  on that same number. If the process exits in between and the pid is
  recycled for a root-owned one, an unprivileged caller can get a process
  it doesn't own moved into a scope it controls -- and then kill it. The
  window is tiny and exploiting it means driving pid wraparound, but it's
  real. The fix is to pin the process identity across the whole operation
  with an `O_PATH` fd on `/proc/<pid>` (or a pidfd): read uid and current
  cgroup through it, act, re-validate, undo on mismatch.
- **`Terminate` is racy by construction.** It walks `cgroup.procs` and
  signals pids one at a time, so a process that forks mid-walk can be
  missed, and a pid that exits mid-walk can be recycled and signalled by
  mistake. `Kill` has neither problem (`cgroup.kill` is atomic and
  recursive) but is SIGKILL-only. Freezing the cgroup around the walk
  would close both.
- **A `Create()`-d scope that never gets a member is never collected**
  until the next restart, since the GC only fires on a real 1 -> 0
  transition. A client that calls `Create` and then dies leaks an empty
  directory.
- **The restart sweep can't tell a pending scope from garbage.** A scope
  `Create()`-d right before a crash, with its `Move()` not yet landed,
  looks exactly like stale leftovers on disk: an empty leaf directory. The
  sweep removes both, so the caller that was about to `Move()` into it
  gets `FileNotFound` instead of succeeding.
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
