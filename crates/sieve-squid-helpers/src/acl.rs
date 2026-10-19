use std::collections::HashMap;
use std::time::Duration;

use chrono::Timelike;
use log::{debug, info, warn};
use sieve_common::database::{PgConnection, WorkspaceId, devices, sites};
use sqlx::PgPool;
use tokio::time::Instant;

use crate::protocol::field;

/// How long a proxy user's workspace is remembered, which bounds how long a revoked device's
/// requests are still evaluated.
const WORKSPACE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclDecision {
    Allow,
    ExplicitDeny,
    ImplicitDeny,
}

impl AclDecision {
    pub fn is_explicit(&self) -> bool {
        matches!(self, Self::Allow | Self::ExplicitDeny)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "OK",
            Self::ImplicitDeny | Self::ExplicitDeny => "ERR",
        }
    }
}

#[derive(Debug, Clone)]
struct Request {
    id: u32,
    user: Option<Box<str>>,
    url: url::Url,
    proxy_origin_url: Option<url::Url>,
}

impl Request {
    fn new_id() -> u32 {
        let now = chrono::Utc::now();
        now.timestamp()
            .to_le_bytes()
            .into_iter()
            .chain(now.nanosecond().to_le_bytes())
            .fold(5381u32, |hash, b| {
                (hash << 5).wrapping_add(hash).wrapping_add(b as u32)
            })
    }

    fn new(user: &str, url: &str, proxy_origin_url: Option<&str>) -> Result<Self, url::ParseError> {
        Ok(Self {
            id: Self::new_id(),
            user: field(user),
            url: url::Url::parse(url)?,
            proxy_origin_url: if let Some(url) = proxy_origin_url {
                Some(url::Url::parse(url)?)
            } else {
                None
            },
        })
    }

    fn arg_to_option(arg: &str) -> Option<&str> {
        if arg == "-" { None } else { Some(arg) }
    }
}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.id)
    }
}

impl TryFrom<&str> for Request {
    type Error = url::ParseError;

    /// `%un %>ru %{X-Proxy-Origin-Url}>h`, plus the `%DATA` field Squid appends when the ACL has
    /// no arguments.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split_whitespace().collect();

        match parts.as_slice() {
            [user, url, proxy_origin_url] | [user, url, proxy_origin_url, _] => {
                Self::new(user, url, Self::arg_to_option(proxy_origin_url))
            }
            _ => Err(url::ParseError::EmptyHost),
        }
    }
}

/// Maps proxy usernames to their device's workspace, briefly remembering the answer.
pub struct Workspaces {
    pool: PgPool,
    known: HashMap<Box<str>, (Option<WorkspaceId>, Instant)>,
}

impl Workspaces {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            known: HashMap::new(),
        }
    }

    /// None for unknown users and revoked devices.
    async fn resolve(&mut self, user: &str) -> Result<Option<WorkspaceId>, sqlx::Error> {
        if let Some((workspace, at)) = self.known.get(user)
            && at.elapsed() < WORKSPACE_TTL
        {
            return Ok(*workspace);
        }

        let mut conn = self.pool.acquire().await?;
        let workspace = devices::find_proxy_credentials(&mut conn, user)
            .await?
            .map(|(workspace, _)| workspace);

        self.known.retain(|_, (_, at)| at.elapsed() < WORKSPACE_TTL);
        self.known.insert(user.into(), (workspace, Instant::now()));
        Ok(workspace)
    }
}

pub async fn decide(
    pool: &PgPool,
    workspaces: &mut Workspaces,
    line: &str,
) -> Result<AclDecision, Box<dyn std::error::Error>> {
    let request = Request::try_from(line.trim())?;
    debug!("({request}) parsed '{line}'");

    let Some(user) = &request.user else {
        warn!("({request}) no proxy user; is proxy authentication required before this ACL?");
        return Ok(AclDecision::ExplicitDeny);
    };

    let Some(workspace) = workspaces.resolve(user).await? else {
        warn!("({request}) unknown or revoked proxy user {user}");
        return Ok(AclDecision::ExplicitDeny);
    };

    let mut conn = pool.acquire().await?;
    let decision = process_request(&mut conn, workspace, &request).await?;
    info!("({request}) {user} {} -> {decision:?}", request.url);
    Ok(decision)
}

async fn process_request(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    request: &Request,
) -> Result<AclDecision, Box<dyn std::error::Error>> {
    let decision = evaluate_url(conn, workspace, request, &request.url).await?;

    if decision.is_explicit() {
        return Ok(decision);
    }

    let Some(proxy_origin_url) = &request.proxy_origin_url else {
        return Ok(decision);
    };

    if !proxy_origin_url.has_host() {
        warn!("({request}) invalid proxy origin url: bad host");
        return Ok(decision);
    }

    debug!("({request}) evaluating X-Proxy-Origin-Url");
    match evaluate_url(conn, workspace, request, proxy_origin_url).await {
        Ok(AclDecision::Allow) => Ok(AclDecision::Allow),
        Ok(_) => Ok(decision),
        Err(e) => {
            warn!("({request}) error occured while processing proxy origin url: {e}");
            Ok(decision)
        }
    }
}

async fn evaluate_url(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    request: &Request,
    url: &url::Url,
) -> Result<AclDecision, Box<dyn std::error::Error>> {
    let domain = url.host_str().unwrap_or("");

    let Ok(scheme) = url.scheme().try_into() else {
        warn!("({request}) unknown url scheme: '{}'", url.scheme());
        return Ok(AclDecision::ImplicitDeny);
    };

    let (domain_id, decision) = match sites::query_domain(conn, workspace, scheme, domain).await? {
        Some((id, Some(true))) => (id, AclDecision::Allow),
        Some((id, Some(false))) => (id, AclDecision::ExplicitDeny),
        Some((id, None)) => (id, AclDecision::ImplicitDeny),
        None => {
            debug!("({request}) {domain} not found in database");
            return Ok(AclDecision::ImplicitDeny);
        }
    };

    let decision = match (
        decision,
        sites::query_path(conn, domain_id, url.path()).await?,
    ) {
        (AclDecision::Allow, Some(false)) => {
            debug!("({request}) domain allow overriden by path deny (path blacklisting)");
            AclDecision::ExplicitDeny
        }
        (AclDecision::ExplicitDeny | AclDecision::ImplicitDeny, Some(true)) => {
            debug!("({request}) domain deny overriden by path allow (path whitelisting)");
            AclDecision::Allow
        }
        (AclDecision::ImplicitDeny, Some(false)) => AclDecision::ExplicitDeny,
        (decision, _) => decision,
    };

    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sieve_common::database::sites::Scheme;
    use sieve_common::database::workspaces;
    use sqlx::pool::PoolConnection;
    use sqlx::postgres::Postgres;

    async fn open(pool: &PgPool) -> (PoolConnection<Postgres>, WorkspaceId) {
        let mut conn = pool.acquire().await.unwrap();
        let ws = workspaces::create(&mut conn, "test").await.unwrap();
        (conn, ws)
    }

    /// Evaluates `url origin data` against `ws`, as if from an already-resolved proxy user.
    async fn decide(conn: &mut PgConnection, ws: WorkspaceId, line: &str) -> AclDecision {
        let request = Request::try_from(format!("dev-test {line}").as_str()).unwrap();
        process_request(conn, ws, &request).await.unwrap()
    }

    #[test]
    fn parses_user_url_origin_and_data() {
        let request = Request::try_from("dev%2Dab https://a.com/x https://b.com/ -").unwrap();
        assert_eq!(request.user.as_deref(), Some("dev-ab"));
        assert_eq!(request.url.as_str(), "https://a.com/x");
        assert_eq!(request.proxy_origin_url.unwrap().as_str(), "https://b.com/");

        let request = Request::try_from("- https://a.com/ -").unwrap();
        assert_eq!(request.user, None);
        assert_eq!(request.proxy_origin_url, None);

        assert!(Request::try_from("https://a.com/").is_err());
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn requests_use_the_proxy_users_workspace(pool: PgPool) {
        use sieve_common::database::devices;

        let (mut conn, home) = open(&pool).await;
        let c = &mut *conn;
        let school = workspaces::create(c, "school").await.unwrap();
        sites::add_domain(c, home, Scheme::Https, "games.com", Some(true))
            .await
            .unwrap();
        sites::add_domain(c, school, Scheme::Https, "games.com", Some(false))
            .await
            .unwrap();
        let laptop = devices::create(c, home, "laptop", "dev-home", "hash")
            .await
            .unwrap();
        devices::create(c, school, "chromebook", "dev-school", "hash")
            .await
            .unwrap();

        let mut workspaces = Workspaces::new(pool.clone());
        let mut ask = async |line: &str| super::decide(&pool, &mut workspaces, line).await.unwrap();

        assert_eq!(
            ask("dev-home https://games.com/ - -").await,
            AclDecision::Allow
        );
        assert_eq!(
            ask("dev-school https://games.com/ - -").await,
            AclDecision::ExplicitDeny
        );
        assert_eq!(
            ask("dev-nobody https://games.com/ - -").await,
            AclDecision::ExplicitDeny
        );
        assert_eq!(
            ask("- https://games.com/ - -").await,
            AclDecision::ExplicitDeny
        );

        devices::revoke(c, laptop.id, None).await.unwrap();
        drop(ask);
        workspaces.known.clear();
        assert_eq!(
            super::decide(&pool, &mut workspaces, "dev-home https://games.com/ - -")
                .await
                .unwrap(),
            AclDecision::ExplicitDeny,
            "revoked once the cached workspace expires"
        );
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn approved_origin_allows_unlisted_subresources(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        sites::add_domain(c, ws, Scheme::Https, "wiki.org", Some(true))
            .await
            .unwrap();

        assert_eq!(
            decide(c, ws, "https://cdn.net/a.js https://wiki.org/page -").await,
            AclDecision::Allow
        );
        assert_eq!(
            decide(c, ws, "https://cdn.net/a.js - -").await,
            AclDecision::ImplicitDeny
        );
        assert_eq!(
            decide(c, ws, "https://cdn.net/a.js https://other.org/ -").await,
            AclDecision::ImplicitDeny
        );
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn explicit_deny_wins_over_approved_origin(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let wiki = sites::add_domain(c, ws, Scheme::Https, "wiki.org", Some(true))
            .await
            .unwrap();
        sites::add_path(c, ws, wiki.id(), "/blocked", false)
            .await
            .unwrap();
        sites::add_domain(c, ws, Scheme::Https, "bad.com", Some(false))
            .await
            .unwrap();

        assert_eq!(
            decide(c, ws, "https://wiki.org/blocked https://wiki.org/ok -").await,
            AclDecision::ExplicitDeny
        );
        assert_eq!(
            decide(c, ws, "https://bad.com/x https://wiki.org/ok -").await,
            AclDecision::ExplicitDeny
        );
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn paths_only_domain_allows_same_domain_subresources(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let wiki = sites::add_domain_no_approval(c, ws, Scheme::Https, "en.wikipedia.org")
            .await
            .unwrap();
        sites::add_path(c, ws, wiki.id(), "/wiki/Enrique_Iglesias", true)
            .await
            .unwrap();
        sites::add_path(c, ws, wiki.id(), "/wiki/Blocked", false)
            .await
            .unwrap();
        let page = "https://en.wikipedia.org/wiki/Enrique_Iglesias";

        assert_eq!(
            decide(c, ws, &format!("{page} - -")).await,
            AclDecision::Allow
        );
        assert_eq!(
            decide(
                c,
                ws,
                &format!("https://en.wikipedia.org/w/load.php {page} -")
            )
            .await,
            AclDecision::Allow
        );
        assert_eq!(
            decide(c, ws, "https://en.wikipedia.org/wiki/Other - -").await,
            AclDecision::ImplicitDeny
        );
        assert_eq!(
            decide(c, ws, "https://en.wikipedia.org/w/load.php - -").await,
            AclDecision::ImplicitDeny
        );
        assert_eq!(
            decide(
                c,
                ws,
                &format!("https://en.wikipedia.org/wiki/Blocked {page} -")
            )
            .await,
            AclDecision::ExplicitDeny
        );
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn denied_domain_blocks_same_domain_subresources(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let wiki = sites::add_domain(c, ws, Scheme::Https, "en.wikipedia.org", Some(false))
            .await
            .unwrap();
        sites::add_path(c, ws, wiki.id(), "/wiki/Enrique_Iglesias", true)
            .await
            .unwrap();

        assert_eq!(
            decide(
                c,
                ws,
                "https://en.wikipedia.org/w/load.php https://en.wikipedia.org/wiki/Enrique_Iglesias -"
            )
            .await,
            AclDecision::ExplicitDeny
        );
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn query_strings_are_ignored(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let yt = sites::add_domain(c, ws, Scheme::Https, "youtube.com", Some(false))
            .await
            .unwrap();
        sites::add_path(c, ws, yt.id(), "/watch", true)
            .await
            .unwrap();

        assert_eq!(
            decide(c, ws, "https://youtube.com/watch?v=abc - -").await,
            AclDecision::Allow
        );
        assert_eq!(
            decide(c, ws, "https://youtube.com/shorts/abc - -").await,
            AclDecision::ExplicitDeny
        );
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn rules_from_other_workspaces_do_not_apply(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let other = workspaces::create(c, "other").await.unwrap();
        sites::add_domain(c, other, Scheme::Https, "wiki.org", Some(true))
            .await
            .unwrap();

        assert_eq!(
            decide(c, ws, "https://wiki.org/ - -").await,
            AclDecision::ImplicitDeny
        );
        assert_eq!(
            decide(c, other, "https://wiki.org/ - -").await,
            AclDecision::Allow
        );
    }
}
