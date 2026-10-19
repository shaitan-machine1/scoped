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
real cgroup v2 filesystem and a real D-Bus system bus: `Create`/`Move`/
`ScopeOf`/`List`, graceful `Terminate` vs. forceful `Kill`, policy
(non-root denial), and restart survival (a hard-killed `scoped`, restarted
against the same cgroup subtree, sweeps never-populated scopes and resumes
watching populated ones). These are `#[ignore]`d by default, so a plain
`cargo test` never touches real cgroups:

```sh
sudo -E cargo test -p scoped --test e2e -- --ignored --test-threads=4
```

## Running it by hand

```sh
# Against the session bus, for poking at it without root or a system-bus
# policy file:
cargo run -p scoped -- --bus session --cgroup-mount /tmp/cgroup-test --scope-root scoped

# Production: system bus, real cgroup2 mount, default scope root
# (/sys/fs/cgroup/scoped). Needs root (or a delegated, writable subtree).
sudo cargo run -p scoped -- --bus system
```

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
| `List(prefix)` | `s` -> `as` | Every descendant under `prefix`, not including `prefix` itself. |
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

### Accepted limitations (carried over from the plan)

- A scope `Create()`-d right before a crash, with its `Move()` not yet
  landed, is indistinguishable on disk from stale leftover garbage: both
  are an empty leaf directory. The restart sweep removes both; the caller
  that was about to `Move()` into it gets `FileNotFound` instead of
  succeeding.
- `ScopeOf`/ownership checks assume `scoped` and the processes it manages
  share the host's cgroup namespace (true for a normal, non-containerized
  deployment; `/proc/<pid>/cgroup` paths are otherwise relative to the
  *reader's* cgroup namespace, not the target's).
