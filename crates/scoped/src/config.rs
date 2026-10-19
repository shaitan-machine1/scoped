use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Bus {
    /// The system bus. What `scoped` runs on in production.
    System,
    /// The session bus. Handy for local development without root or a
    /// system-bus policy file installed.
    Session,
}

/// `scoped`: cgroup v2 scope manager (create, move, terminate, kill, by
/// scope ID).
#[derive(Debug, Parser)]
#[command(name = "scoped", version)]
pub struct Config {
    /// Where cgroup v2 is mounted.
    #[arg(long, default_value = "/sys/fs/cgroup")]
    pub cgroup_mount: PathBuf,

    /// Single path segment under `--cgroup-mount` that `scoped` manages
    /// exclusively. Must already be delegated to `scoped` (writable by the
    /// user it runs as).
    #[arg(long, default_value = "scoped")]
    pub scope_root: String,

    /// Which bus to serve the manager object on. Both honor the usual
    /// `DBUS_SYSTEM_BUS_ADDRESS` / `DBUS_SESSION_BUS_ADDRESS` environment
    /// variables, which is how `tests/e2e.rs` points `scoped` at the
    /// private bus it runs each case against.
    #[arg(long, value_enum, default_value_t = Bus::System)]
    pub bus: Bus,
}
