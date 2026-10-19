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
    connection.request_name(dbus::BUS_NAME).await?;
    tracing::info!(name = dbus::BUS_NAME, path = dbus::OBJECT_PATH, "serving");

    // The connection runs on its own helper thread/task from here on (see
    // the zbus README's "Compatibility with async runtimes" section); we
    // just need to keep the process alive.
    //
    // TODO(M0+): handle SIGTERM/SIGINT for a clean exit. Not required yet:
    // scoped keeps no state outside the cgroup tree, so there is nothing to
    // flush, and the watcher threads hold no resources the kernel won't
    // reclaim on process exit.
    std::future::pending::<()>().await;
    Ok(())
}
