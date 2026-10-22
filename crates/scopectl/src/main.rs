use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use scope_id::ScopeId;
use std::fmt::Write;
use std::process::ExitCode;

#[zbus::proxy(
    interface = "org.decoupling.scoped1.Manager",
    default_service = "org.decoupling.scoped1",
    default_path = "/org/decoupling/scoped1"
)]
trait Scoped {
    fn list(&self, prefix: &str) -> zbus::Result<Vec<String>>;
    fn scope_of(&self, pid: u32) -> zbus::Result<String>;
    fn terminate_scope(&self, id: &str) -> zbus::Result<()>;
    fn kill_scope(&self, id: &str) -> zbus::Result<()>;
}

#[derive(Debug, Parser)]
#[command(version, about = "Inspect and administer scoped scopes")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List managed scopes below a prefix.
    List {
        #[arg(value_parser = parse_scope)]
        prefix: String,
    },
    /// Show the managed scope containing a process.
    ScopeOf { pid: u32 },
    /// Send SIGTERM to every process below a scope.
    Terminate {
        #[arg(value_parser = parse_scope)]
        id: String,
    },
    /// Immediately SIGKILL every process below a scope.
    Kill {
        #[arg(value_parser = parse_scope)]
        id: String,
    },
}

fn parse_scope(value: &str) -> std::result::Result<String, String> {
    ScopeId::parse(value)
        .map(String::from)
        .map_err(|error| error.to_string())
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("scopectl: create async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(Args::parse())) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("scopectl: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<String> {
    let connection = zbus::Connection::system()
        .await
        .context("connect to the system bus")?;
    let proxy = ScopedProxy::new(&connection)
        .await
        .context("create scoped D-Bus proxy")?;
    match args.command {
        Command::List { prefix } => {
            let scopes = proxy
                .list(&prefix)
                .await
                .with_context(|| format!("call scoped List for prefix {prefix}"))?;
            Ok(format_scopes(&scopes))
        }
        Command::ScopeOf { pid } => {
            let scope = proxy
                .scope_of(pid)
                .await
                .with_context(|| format!("call scoped ScopeOf for PID {pid}"))?;
            Ok(format_scope_of(pid, &scope))
        }
        Command::Terminate { id } => {
            proxy
                .terminate_scope(&id)
                .await
                .with_context(|| format!("call scoped TerminateScope for {id}"))?;
            Ok(format!("Termination requested for scope {id}.\n"))
        }
        Command::Kill { id } => {
            proxy
                .kill_scope(&id)
                .await
                .with_context(|| format!("call scoped KillScope for {id}"))?;
            Ok(format!("Immediate kill requested for scope {id}.\n"))
        }
    }
}

fn format_scopes(scopes: &[String]) -> String {
    if scopes.is_empty() {
        return "No matching scopes.\n".to_owned();
    }
    let mut output = "SCOPE\n".to_owned();
    for scope in scopes {
        writeln!(output, "{scope}").expect("writing to String cannot fail");
    }
    output
}

fn format_scope_of(pid: u32, scope: &str) -> String {
    if scope.is_empty() {
        return format!("PID {pid} is not in a managed scope.\n");
    }
    let pid_width = pid.to_string().len().max("PID".len());
    format!("{:>pid_width$}  SCOPE\n{pid:>pid_width$}  {scope}\n", "PID")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    const SCOPE: &str = "sessiond/user/1000/session/0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_all_commands() {
        assert!(matches!(
            Args::try_parse_from(["scopectl", "list", "sessiond"])
                .expect("list parses")
                .command,
            Command::List { prefix } if prefix == "sessiond"
        ));
        assert!(matches!(
            Args::try_parse_from(["scopectl", "scope-of", "123"])
                .expect("scope-of parses")
                .command,
            Command::ScopeOf { pid: 123 }
        ));
        assert!(matches!(
            Args::try_parse_from(["scopectl", "terminate", SCOPE])
                .expect("terminate parses")
                .command,
            Command::Terminate { id } if id == SCOPE
        ));
        assert!(matches!(
            Args::try_parse_from(["scopectl", "kill", SCOPE])
                .expect("kill parses")
                .command,
            Command::Kill { id } if id == SCOPE
        ));
    }

    #[test]
    fn rejects_malformed_arguments() {
        let scope = Args::try_parse_from(["scopectl", "list", "/absolute"])
            .expect_err("invalid scope is rejected");
        assert_eq!(scope.kind(), ErrorKind::ValueValidation);
        let pid = Args::try_parse_from(["scopectl", "scope-of", "not-a-pid"])
            .expect_err("invalid pid is rejected");
        assert_eq!(pid.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn renders_list_and_empty_state() {
        assert_eq!(format_scopes(&[]), "No matching scopes.\n");
        assert_eq!(
            format_scopes(&["z/scope".to_owned(), "a/scope".to_owned()]),
            "SCOPE\nz/scope\na/scope\n"
        );
    }

    #[test]
    fn renders_scope_lookup_and_successful_absence() {
        assert_eq!(
            format_scope_of(7, SCOPE),
            format!("PID  SCOPE\n  7  {SCOPE}\n")
        );
        assert_eq!(
            format_scope_of(99, ""),
            "PID 99 is not in a managed scope.\n"
        );
    }

    #[test]
    fn renders_contextual_dbus_errors() {
        let error = anyhow::anyhow!("org.decoupling.scoped1.Error.AccessDenied: root only")
            .context("call scoped KillScope for abc");
        assert_eq!(
            format!("{error:#}"),
            "call scoped KillScope for abc: org.decoupling.scoped1.Error.AccessDenied: root only"
        );
    }
}
