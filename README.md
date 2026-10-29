# scoped (retired source repository)

The scoped daemon, D-Bus API, and standalone `scope-id` release were retired by
the synchronous session-stack migration. Their maintained implementation now
lives in [`lib-scoped` in the sessiond repository](https://github.com/shaitan-machine1/sessiond/tree/master/crates/lib-scoped).

`lib-scoped` is a synchronous, daemonless Rust library. Callers open or create
an explicit cgroup-v2 domain, perform containment operations directly, and own
all locking, observation threads, and cleanup policy. It has no D-Bus service,
async runtime, hidden worker, or automatic garbage collection.

This repository intentionally contains no build target. Distribution package
and installed-service removal are separate deployment work and are not encoded
here.
