use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use reqwest::Client;
use sieve_common::database::notify;
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::time::{Instant, MissedTickBehavior};

use crate::update::{self, Config, Scope};

/// How long to wait after a change before fetching, so a burst of edits becomes one pass.
pub const DEBOUNCE: Duration = Duration::from_secs(2);
pub const FULL_PASS_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

async fn listen(pool: &PgPool) -> PgListener {
    loop {
        let result = async {
            let mut listener = PgListener::connect_with(pool).await?;
            listener.listen(notify::ENTRIES).await?;
            Ok::<_, sqlx::Error>(listener)
        }
        .await;

        match result {
            Ok(listener) => {
                info!("listening for {}", notify::ENTRIES);
                return listener;
            }
            Err(e) => {
                error!("failed to listen for {}: {e}", notify::ENTRIES);
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

/// Runs `pass` for every workspace at startup and every `full_interval`, and for each workspace
/// whose entries change, `debounce` after the first change. Never returns.
pub async fn run<F, Fut>(pool: PgPool, mut pass: F, debounce: Duration, full_interval: Duration)
where
    F: FnMut(Scope) -> Fut,
    Fut: Future<Output = ()>,
{
    // Listen before the first pass, so entries added while it runs aren't missed.
    let mut listener = listen(&pool).await;
    pass(Scope::All).await;

    let mut full = tokio::time::interval_at(Instant::now() + full_interval, full_interval);
    full.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut pending = HashSet::new();
    let mut deadline: Option<Instant> = None;

    loop {
        tokio::select! {
            received = listener.try_recv() => match received {
                Ok(Some(notification)) => match notification.payload().parse() {
                    Ok(workspace) => {
                        pending.insert(workspace);
                        deadline.get_or_insert_with(|| Instant::now() + debounce);
                    }
                    Err(e) => warn!("ignoring notification '{}': {e}", notification.payload()),
                },
                // try_recv reconnects on the next call; anything sent in between is lost.
                Ok(None) => {
                    warn!("notification listener lost its connection; running a full pass");
                    pending.clear();
                    deadline = None;
                    pass(Scope::All).await;
                }
                Err(e) => {
                    error!("notification listener failed: {e}");
                    tokio::time::sleep(RECONNECT_DELAY).await;
                    listener = listen(&pool).await;
                    pending.clear();
                    deadline = None;
                    pass(Scope::All).await;
                }
            },
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {
                deadline = None;
                for workspace in pending.drain().collect::<Vec<_>>() {
                    pass(Scope::Workspace(workspace)).await;
                }
            }
            _ = full.tick() => {
                pending.clear();
                deadline = None;
                pass(Scope::All).await;
            }
        }
    }
}

/// The long-running service: `run` with real metadata passes.
pub async fn serve(pool: PgPool, client: Client, config: Config) {
    let config = Arc::new(config);
    let database = pool.clone();

    let pass = move |scope: Scope| {
        let (pool, client, config) = (database.clone(), client.clone(), Arc::clone(&config));
        async move {
            info!("updating metadata for {scope}");
            let result = match pool.acquire().await {
                Ok(mut conn) => update::update(&mut conn, &client, &config, scope, false).await,
                Err(e) => Err(e.into()),
            };
            if let Err(e) = result {
                error!("metadata update for {scope} failed: {e}");
            }
        }
    };

    run(pool, pass, DEBOUNCE, FULL_PASS_INTERVAL).await;
}

#[cfg(test)]
mod tests {
    use sieve_common::database::sites::{self, Scheme};
    use sieve_common::database::workspaces;
    use tokio::sync::mpsc;

    use super::*;

    async fn next(passes: &mut mpsc::UnboundedReceiver<Scope>, wait: Duration) -> Option<Scope> {
        tokio::time::timeout(wait, passes.recv()).await.ok().flatten()
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn passes_follow_entry_changes(pool: PgPool) {
        let (sender, mut passes) = mpsc::unbounded_channel();
        let recorder = move |scope| {
            sender.send(scope).unwrap();
            async {}
        };
        let service =
            tokio::spawn(run(pool.clone(), recorder, Duration::from_millis(200), Duration::from_secs(3600)));

        assert_eq!(next(&mut passes, Duration::from_secs(5)).await, Some(Scope::All));

        let mut conn = pool.acquire().await.unwrap();
        let c = &mut *conn;
        let a = workspaces::create(c, "a").await.unwrap();
        let b = workspaces::create(c, "b").await.unwrap();
        let domain = sites::add_domain(c, a, Scheme::Https, "one.com", Some(true)).await.unwrap();
        sites::add_domain(c, a, Scheme::Https, "two.com", Some(true)).await.unwrap();
        sites::add_path(c, a, domain.id(), "/page", true).await.unwrap();
        sites::add_domain(c, b, Scheme::Https, "three.com", Some(true)).await.unwrap();

        let mut scopes = vec![
            next(&mut passes, Duration::from_secs(2)).await,
            next(&mut passes, Duration::from_secs(2)).await,
        ];
        scopes.sort_by_key(|scope| *scope == Some(Scope::Workspace(b)));
        assert_eq!(scopes, [Some(Scope::Workspace(a)), Some(Scope::Workspace(b))]);
        assert_eq!(next(&mut passes, Duration::from_millis(500)).await, None, "changes were batched");

        // The cache's own writes must not wake it again.
        sites::set_domain_metadata(c, domain.id(), Some("One"), None, None).await.unwrap();
        assert_eq!(next(&mut passes, Duration::from_millis(500)).await, None);

        // Its listener connection would otherwise hold up the test database's teardown.
        service.abort();
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn full_passes_repeat(pool: PgPool) {
        let (sender, mut passes) = mpsc::unbounded_channel();
        let recorder = move |scope| {
            sender.send(scope).unwrap();
            async {}
        };
        let service =
            tokio::spawn(run(pool, recorder, Duration::from_millis(50), Duration::from_millis(200)));

        for _ in 0..3 {
            assert_eq!(next(&mut passes, Duration::from_secs(5)).await, Some(Scope::All));
        }

        service.abort();
    }
}
