use std::io::BufRead;
use std::process::ExitCode;

use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use sieve_common::audit::{self, Action, Actor, Filter, Target, TargetKind};
use sieve_common::database::workspaces::{self, Role};
use sieve_common::database::{self, PgConnection, WorkspaceId, users};
use sieve_common::jwt::Keys;
use sieve_common::{config, enrollment, password};
use sqlx::Connection;
use uuid::Uuid;

type Error = Box<dyn std::error::Error + Send + Sync>;

const MIN_PASSWORD_LEN: usize = 8;

#[derive(Parser)]
#[command(name = "sieve", about = "Sieve administration commands")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage users and passwords
    #[command(subcommand)]
    User(UserCommand),
    /// Manage workspaces and their members
    #[command(subcommand)]
    Workspace(WorkspaceCommand),
    /// Enroll and revoke client devices
    #[command(subcommand)]
    Device(DeviceCommand),
    /// Read the audit log
    #[command(subcommand)]
    Audit(AuditCommand),
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a user, prompting for their password
    Create {
        username: Box<str>,
        /// Read the password from the first line of stdin instead of prompting
        #[arg(long)]
        password_stdin: bool,
    },
    /// Change a user's password
    Passwd {
        username: Box<str>,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliRole {
    Owner,
    Member,
}

impl From<CliRole> for Role {
    fn from(role: CliRole) -> Self {
        match role {
            CliRole::Owner => Role::Owner,
            CliRole::Member => Role::Member,
        }
    }
}

#[derive(Subcommand)]
enum WorkspaceCommand {
    /// Create a workspace and print its id
    Create { name: Box<str> },
    /// Add a user to a workspace, or change their role
    AddMember {
        workspace: WorkspaceId,
        username: Box<str>,
        #[arg(long, value_enum, default_value = "member")]
        role: CliRole,
    },
    /// Remove a user from a workspace
    RemoveMember {
        workspace: WorkspaceId,
        username: Box<str>,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Register a device and print its token and proxy credentials
    Create { workspace: WorkspaceId, name: Box<str> },
    /// Revoke a device's token and proxy credentials
    Revoke { device: Uuid },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Print audit log entries, newest first
    List {
        #[arg(long)]
        workspace: Option<WorkspaceId>,
        /// RFC 3339 timestamp or YYYY-MM-DD (UTC)
        #[arg(long, value_parser = parse_since)]
        since: Option<DateTime<Utc>>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
}

fn parse_since(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|time| time.with_timezone(&Utc))
        .or_else(|_| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d").map(|date| date.and_time(Default::default()).and_utc())
        })
        .map_err(|_| "expected an RFC 3339 timestamp or YYYY-MM-DD".into())
}

fn read_password(from_stdin: bool) -> Result<Box<str>, Error> {
    let password = if from_stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        let password = rpassword::prompt_password("Password: ")?;
        if rpassword::prompt_password("Repeat password: ")? != password {
            return Err("passwords do not match".into());
        }
        password
    };

    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!("password must be at least {MIN_PASSWORD_LEN} characters").into());
    }
    Ok(password.into())
}

async fn find_user(conn: &mut PgConnection, username: &str) -> Result<users::User, Error> {
    users::find_by_username(conn, username)
        .await?
        .ok_or_else(|| format!("no user named '{username}'").into())
}

async fn require_workspace(conn: &mut PgConnection, workspace: WorkspaceId) -> Result<(), Error> {
    if workspaces::exists(conn, workspace).await? {
        Ok(())
    } else {
        Err(format!("no workspace with id {workspace}").into())
    }
}

async fn user(conn: &mut PgConnection, command: UserCommand) -> Result<(), Error> {
    let actor = Actor::cli();
    let (username, password_stdin, creating) = match &command {
        UserCommand::Create { username, password_stdin } => (username, *password_stdin, true),
        UserCommand::Passwd { username, password_stdin } => (username, *password_stdin, false),
    };

    let password = read_password(password_stdin)?;
    let hash = tokio::task::spawn_blocking(move || password::hash(&password))
        .await?
        .map_err(|e| format!("failed to hash password: {e}"))?;

    let mut tx = conn.begin().await?;
    let (user, action) = if creating {
        (users::create(&mut tx, username, &hash).await?, Action::UserCreate)
    } else {
        let user = users::set_password_hash(&mut tx, username, &hash)
            .await?
            .ok_or_else(|| format!("no user named '{username}'"))?;
        (user, Action::UserPasswd)
    };

    audit::record(
        &mut tx,
        &actor,
        None,
        action,
        Some(Target::new(TargetKind::User, user.id)),
        json!({ "username": user.username }),
    )
    .await?;
    tx.commit().await?;

    if creating {
        println!("created user '{}' ({})", user.username, user.id);
    } else {
        println!("changed password for '{}'", user.username);
    }
    Ok(())
}

async fn workspace(conn: &mut PgConnection, command: WorkspaceCommand) -> Result<(), Error> {
    let actor = Actor::cli();
    let mut tx = conn.begin().await?;

    match command {
        WorkspaceCommand::Create { name } => {
            let id = workspaces::create(&mut tx, &name).await?;
            audit::record(
                &mut tx,
                &actor,
                Some(id),
                Action::WorkspaceCreate,
                Some(Target::new(TargetKind::Workspace, id)),
                json!({ "name": name }),
            )
            .await?;
            tx.commit().await?;
            println!("{id}");
        }
        WorkspaceCommand::AddMember { workspace, username, role } => {
            require_workspace(&mut tx, workspace).await?;
            let user = find_user(&mut tx, &username).await?;
            let role = Role::from(role);
            workspaces::add_member(&mut tx, workspace, user.id, role).await?;
            audit::record(
                &mut tx,
                &actor,
                Some(workspace),
                Action::MemberAdd,
                Some(Target::new(TargetKind::User, user.id)),
                json!({ "username": user.username, "role": role }),
            )
            .await?;
            tx.commit().await?;
            println!("'{}' is now {} of {workspace}", user.username, role.as_str());
        }
        WorkspaceCommand::RemoveMember { workspace, username } => {
            require_workspace(&mut tx, workspace).await?;
            let user = find_user(&mut tx, &username).await?;
            if !workspaces::remove_member(&mut tx, workspace, user.id).await? {
                return Err(format!("'{username}' is not a member of {workspace}").into());
            }
            audit::record(
                &mut tx,
                &actor,
                Some(workspace),
                Action::MemberRemove,
                Some(Target::new(TargetKind::User, user.id)),
                json!({ "username": user.username }),
            )
            .await?;
            tx.commit().await?;
            println!("removed '{}' from {workspace}", user.username);
        }
    }
    Ok(())
}

async fn device(conn: &mut PgConnection, command: DeviceCommand) -> Result<(), Error> {
    let actor = Actor::cli();
    let mut tx = conn.begin().await?;

    match command {
        DeviceCommand::Create { workspace, name } => {
            let keys = Keys::from_env()?;
            require_workspace(&mut tx, workspace).await?;
            let new = enrollment::enroll(&mut tx, &keys, &actor, workspace, &name).await?;
            tx.commit().await?;
            println!("device:         {}", new.device.id);
            println!("token:          {}", new.token);
            println!("proxy username: {}", new.device.proxy_username);
            println!("proxy password: {}", new.proxy_password);
            eprintln!("the token and proxy password are not stored and cannot be shown again");
        }
        DeviceCommand::Revoke { device } => {
            let revoked = enrollment::revoke(&mut tx, &actor, device, None)
                .await?
                .ok_or_else(|| format!("no active device with id {device}"))?;
            tx.commit().await?;
            println!("revoked '{}' ({})", revoked.name, revoked.id);
        }
    }
    Ok(())
}

async fn audit_log(conn: &mut PgConnection, command: AuditCommand) -> Result<(), Error> {
    let AuditCommand::List { workspace, since, limit } = command;
    let filter = Filter {
        workspace,
        since,
        limit: limit.max(1),
        ..Default::default()
    };

    for entry in audit::list(conn, &filter).await? {
        let target = match (&entry.target_kind, &entry.target_id) {
            (Some(kind), Some(id)) => format!("{kind}:{id}"),
            _ => "-".into(),
        };
        println!(
            "{}\t{}\t{}:{}\t{}\t{}\t{}",
            entry.occurred_at.to_rfc3339(),
            entry.workspace_id.map_or("-".into(), |ws| ws.to_string()),
            entry.actor_kind,
            entry.actor_label,
            entry.action,
            target,
            entry.details,
        );
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let command = Cli::parse().command;

    let result = async {
        let pool = database::connect(&config::database_url()?, 1).await?;
        database::migrate(&pool).await?;
        let mut conn = pool.acquire().await?;

        match command {
            Command::User(command) => user(&mut conn, command).await,
            Command::Workspace(command) => workspace(&mut conn, command).await,
            Command::Device(command) => device(&mut conn, command).await,
            Command::Audit(command) => audit_log(&mut conn, command).await,
        }
    }
    .await;

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_since() {
        assert_eq!(
            parse_since("2026-10-18").unwrap().to_rfc3339(),
            "2026-10-18T00:00:00+00:00"
        );
        assert_eq!(
            parse_since("2026-10-18T12:30:00+01:00").unwrap().to_rfc3339(),
            "2026-10-18T11:30:00+00:00"
        );
        assert!(parse_since("yesterday").is_err());
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
