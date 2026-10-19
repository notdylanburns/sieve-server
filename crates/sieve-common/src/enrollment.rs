use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use uuid::Uuid;

use crate::audit::{self, Action, Actor, Target, TargetKind};
use crate::database::devices::{self, Device};
use crate::database::{PgConnection, WorkspaceId};
use crate::jwt::Keys;
use crate::password;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// A device with its credentials, which are only available at creation.
pub struct NewDevice {
    pub device: Device,
    pub token: Box<str>,
    pub proxy_password: Box<str>,
}

fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| format!("failed to generate random bytes: {e}"))?;
    Ok(bytes)
}

/// Registers a device, issues its token and proxy credentials, and records it in the audit log.
pub async fn enroll(
    conn: &mut PgConnection,
    keys: &Keys,
    actor: &Actor,
    workspace: WorkspaceId,
    name: &str,
) -> Result<NewDevice, Error> {
    let proxy_username: Box<str> = random_bytes::<6>()?
        .iter()
        .fold(String::from("dev-"), |name, byte| name + &format!("{byte:02x}"))
        .into();
    let proxy_password: Box<str> = URL_SAFE_NO_PAD.encode(random_bytes::<24>()?).into();

    let to_hash = proxy_password.clone();
    let proxy_password_hash = tokio::task::spawn_blocking(move || password::hash(&to_hash))
        .await?
        .map_err(|e| format!("failed to hash proxy password: {e}"))?;

    let device =
        devices::create(conn, workspace, name, &proxy_username, &proxy_password_hash).await?;
    let token = keys.issue_device(device.id, workspace)?;

    audit::record(
        conn,
        actor,
        Some(workspace),
        Action::DeviceCreate,
        Some(Target::new(TargetKind::Device, device.id)),
        json!({ "name": device.name, "proxy_username": device.proxy_username }),
    )
    .await?;

    Ok(NewDevice {
        device,
        token,
        proxy_password,
    })
}

/// Returns None when the device is unknown, already revoked, or (with `workspace`) in another workspace.
pub async fn revoke(
    conn: &mut PgConnection,
    actor: &Actor,
    id: Uuid,
    workspace: Option<WorkspaceId>,
) -> Result<Option<Device>, Error> {
    let Some(device) = devices::revoke(conn, id, workspace).await? else {
        return Ok(None);
    };

    audit::record(
        conn,
        actor,
        Some(device.workspace_id),
        Action::DeviceRevoke,
        Some(Target::new(TargetKind::Device, device.id)),
        json!({ "name": device.name }),
    )
    .await?;

    Ok(Some(device))
}
