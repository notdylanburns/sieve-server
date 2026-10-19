use log::{info, warn};
use sieve_common::database::devices;
use sieve_common::password;
use sqlx::PgPool;

use crate::protocol::field;

/// Answers one Squid basic-auth request: `username password`, both URL-escaped.
/// `OK` for an active device's proxy credentials, `ERR` otherwise, `BH` if the check itself failed.
pub async fn check(pool: &PgPool, line: &str) -> &'static str {
    let Some((username, password)) = line.trim().split_once(' ') else {
        warn!("malformed auth request");
        return "ERR";
    };
    let (Some(username), Some(password)) = (field(username), field(password)) else {
        return "ERR";
    };

    let credentials = match pool.acquire().await {
        Ok(mut conn) => devices::find_proxy_credentials(&mut conn, &username).await,
        Err(e) => Err(e),
    };
    let credentials = match credentials {
        Ok(credentials) => credentials,
        Err(e) => {
            warn!("failed to look up proxy credentials: {e}");
            return "BH";
        }
    };

    let hash = credentials.as_ref().map(|(_, hash)| hash.clone());
    let verified = tokio::task::spawn_blocking(move || match hash {
        Some(hash) => password::verify(&password, &hash),
        None => {
            password::verify_dummy(&password);
            false
        }
    })
    .await;

    match verified {
        Ok(true) => {
            info!("authenticated {username}");
            "OK"
        }
        Ok(false) => {
            warn!("rejected proxy credentials for {username}");
            "ERR"
        }
        Err(e) => {
            warn!("password verification failed: {e}");
            "BH"
        }
    }
}

#[cfg(test)]
mod tests {
    use sieve_common::audit::Actor;
    use sieve_common::database::workspaces;
    use sieve_common::enrollment;
    use sieve_common::jwt::Keys;

    use super::*;

    fn keys() -> Keys {
        Keys::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap()
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn accepts_only_active_device_credentials(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let ws = workspaces::create(&mut conn, "home").await.unwrap();
        let device = enrollment::enroll(&mut conn, &keys(), &Actor::cli(), ws, "laptop").await.unwrap();
        drop(conn);

        let user = &device.device.proxy_username;
        let password = &device.proxy_password;

        assert_eq!(check(&pool, &format!("{user} {password}")).await, "OK");
        assert_eq!(check(&pool, &format!("{user} wrong")).await, "ERR");
        assert_eq!(check(&pool, &format!("dev-unknown {password}")).await, "ERR");
        assert_eq!(check(&pool, "garbage").await, "ERR");
        assert_eq!(check(&pool, &format!("{user} -")).await, "ERR");

        let mut conn = pool.acquire().await.unwrap();
        enrollment::revoke(&mut conn, &Actor::cli(), device.device.id, None).await.unwrap();
        drop(conn);
        assert_eq!(check(&pool, &format!("{user} {password}")).await, "ERR");
    }
}
