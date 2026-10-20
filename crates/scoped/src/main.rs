mod backend;
mod config;
mod dbus;
mod policy;
mod service;
mod watch;

use backend::RealBackend;
use clap::Parser;
use config::{Bus, Config};
use dbus::Manager;
use service::Service;
use std::process::ExitCode;
use std::sync::Arc;
use watch::Watchers;

fn main() -> ExitCode {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match zbus::block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "scoped exited");
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(RealBackend::new(
        config.cgroup_mount.clone(),
        config.scope_root.clone(),
    )?);
    tracing::info!(
        root = %backend.base().display(),
        "managing cgroup v2 scopes under this root"
    );

    let service = Arc::new(Service::new(backend.clone()));

    let builder = match config.bus {
        Bus::System => zbus::connection::Builder::system(),
        Bus::Session => zbus::connection::Builder::session(),
    };
    let connection = builder.build().await?;

    let watchers = Watchers::new(
        backend.clone(),
        connection.clone(),
        zbus::ObjectPath::try_from(dbus::OBJECT_PATH)?.into(),
    );

    tracing::info!("scanning for leftover scopes from a previous run");
    watchers.startup_scan().await;

    let manager = Manager::new(service, watchers);
    connection
        .object_server()
        .at(dbus::OBJECT_PATH, manager)
        .await?;
    // Deliberately *not* zbus's default flags, which are
    // ALLOW_REPLACEMENT | REPLACE_EXISTING | DO_NOT_QUEUE: those let any
    // second instance silently steal the name from the running daemon,
    // which then keeps running unreachable (and, because DO_NOT_QUEUE
    // means it isn't queued either, the name stays unowned once the thief
    // exits). A single root-owned system daemon has no handover protocol,
    // so the correct policy is "first one wins, duplicates fail loudly".
    match connection
        .request_name_with_flags(dbus::BUS_NAME, zbus::fdo::RequestNameFlags::DO_NOT_QUEUE)
        .await
    {
        Ok(_) => {}
        Err(zbus::Error::NameTaken) => {
            return Err(format!(
                "{} is already owned on this bus; another scoped is running",
                dbus::BUS_NAME
            )
            .into());
        }
        Err(e) => return Err(e.into()),
    }
    tracing::info!(name = dbus::BUS_NAME, path = dbus::OBJECT_PATH, "serving");

    // The connection runs on its own helper thread/task from here on (see
    // the zbus README's "Compatibility with async runtimes" section); we
    // just need to keep the process alive for as long as we are actually
    // reachable. Losing the connection means losing the name, and a
    // supervisor can only notice that if the process exits, so treat it as
    // a fatal error: s6 restarts us and `startup_scan` reconstructs the
    // watchers from the cgroup tree.
    //
    // TODO(M0+): handle SIGTERM/SIGINT for a clean exit. Not required yet:
    // scoped keeps no state outside the cgroup tree, so there is nothing to
    // flush, and the watcher threads hold no resources the kernel won't
    // reclaim on process exit.
    connection.closed().await;
    Err("lost the D-Bus connection".into())
}
