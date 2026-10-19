use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sieve_common::audit::{Actor, Filter};
use sieve_common::database::sites::{self, Scheme};
use sieve_common::database::videos::{self, VideoMetadata};
use sieve_common::database::workspaces::{self, Role};
use sieve_common::database::{WorkspaceId, users};
use sieve_common::jwt::Keys;
use sieve_common::{audit, enrollment, password};
use sqlx::PgPool;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message};
use tower::ServiceExt;
use uuid::Uuid;

use crate::events::{self, Hub};
use crate::server;
use crate::state::AppState;

const SECRET: [u8; 32] = [3; 32];

fn keys() -> Keys {
    Keys::from_base64(&STANDARD.encode(SECRET)).unwrap()
}

struct TestApp {
    router: Router,
    pool: PgPool,
    keys: Keys,
    hub: Arc<Hub>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

// Spawned servers and listeners hold database connections, which would otherwise delay the
// test database's teardown until it times out.
impl Drop for TestApp {
    fn drop(&mut self) {
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

impl TestApp {
    fn new(pool: PgPool) -> Self {
        let dir = std::env::temp_dir().join(format!("sieve-test-{}", Uuid::new_v4()));
        let frontend = dir.join("frontend");
        let icons = dir.join("icons");
        std::fs::create_dir_all(&frontend).unwrap();
        std::fs::create_dir_all(&icons).unwrap();
        std::fs::write(frontend.join("index.html"), "<h1>sieve</h1>").unwrap();
        let proxy_ca = dir.join("ca.crt");
        std::fs::write(&proxy_ca, "-----BEGIN CERTIFICATE-----\ntest\n").unwrap();

        let hub = Hub::new(Duration::from_millis(100));
        let state = AppState::new(pool.clone(), keys(), Box::new([]), hub.clone());
        Self {
            router: server::router(state, &icons, &frontend, Some(proxy_ca)),
            pool,
            keys: keys(),
            hub,
            tasks: Default::default(),
        }
    }

    /// Serves over real TCP with the notification listener running, for WebSocket tests.
    async fn serve(&self) -> SocketAddr {
        let (ready, listener_task) = events::spawn_listener(self.pool.clone(), self.hub.clone());
        // Subscribing first would race the listener's reconnect catch-up notification.
        tokio::time::timeout(Duration::from_secs(5), ready.notified()).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let service = self.router.clone().into_make_service_with_connect_info::<SocketAddr>();
        let server = tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
        self.tasks.lock().unwrap().extend([listener_task, server]);
        addr
    }

    async fn enroll(&self, workspace: WorkspaceId, name: &str) -> enrollment::NewDevice {
        let mut conn = self.pool.acquire().await.unwrap();
        enrollment::enroll(&mut conn, &self.keys, &Actor::cli(), workspace, name).await.unwrap()
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, body)
    }

    async fn call(&self, method: Method, uri: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();

        let (status, _, body) = self.send(request).await;
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    async fn user(&self, username: &str, password: &str) -> i64 {
        let hash = password::hash(password).unwrap();
        let mut conn = self.pool.acquire().await.unwrap();
        users::create(&mut conn, username, &hash).await.unwrap().id
    }

    async fn workspace(&self, name: &str) -> WorkspaceId {
        let mut conn = self.pool.acquire().await.unwrap();
        workspaces::create(&mut conn, name).await.unwrap()
    }

    async fn member(&self, workspace: WorkspaceId, user_id: i64, role: Role) {
        let mut conn = self.pool.acquire().await.unwrap();
        workspaces::add_member(&mut conn, workspace, user_id, role).await.unwrap();
    }

    fn token(&self, user_id: i64) -> Box<str> {
        self.keys.issue_user(user_id).unwrap()
    }

    async fn audit(&self, workspace: Option<WorkspaceId>) -> Vec<audit::Entry> {
        let mut conn = self.pool.acquire().await.unwrap();
        audit::list(&mut conn, &Filter { workspace, limit: 100, ..Default::default() })
            .await
            .unwrap()
    }
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn unauthenticated_api_requests_get_401(pool: PgPool) {
    let app = TestApp::new(pool);
    let ws = app.workspace("home").await;

    let (status, _) = app.call(Method::GET, &format!("/api/{ws}/sites/domains"), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = app.call(Method::GET, "/api/auth/me", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = app.call(Method::GET, "/api/auth/me", Some("not-a-jwt"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, _) = app
        .send(Request::get("/static/icons/a.png").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn unauthenticated_pages_redirect_to_login(pool: PgPool) {
    let app = TestApp::new(pool);

    let (status, headers, _) = app
        .send(Request::get("/w/abc/sites?x=1").body(Body::empty()).unwrap())
        .await;
    assert!(status.is_redirection());
    assert_eq!(headers[header::LOCATION], "/login?next=%2Fw%2Fabc%2Fsites%3Fx%3D1");

    let (status, _, body) = app.send(Request::get("/login").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<h1>sieve</h1>");

    let (status, _, _) = app
        .send(Request::get("/assets/missing.js").body(Body::empty()).unwrap())
        .await;
    assert!(!status.is_redirection());

    let user = app.user("amanda", "password1").await;
    let (status, _, _) = app
        .send(
            Request::get("/w/abc/sites")
                .header(header::COOKIE, format!("sieve_session={}", app.token(user)))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn proxy_ca_certificate_is_public(pool: PgPool) {
    let app = TestApp::new(pool);
    let (status, headers, body) = app
        .send(Request::get("/api/proxy-ca.crt").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/x-x509-ca-cert");
    assert!(body.starts_with(b"-----BEGIN CERTIFICATE-----"));
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn unknown_api_paths_are_404(pool: PgPool) {
    let app = TestApp::new(pool);
    let (status, _) = app.call(Method::GET, "/api/nothing/here", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn login_sets_session_cookie_and_is_audited(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.user("amanda", "password1").await;
    let ws = app.workspace("home").await;
    app.member(ws, user, Role::Owner).await;

    let login = |username: &str, password: &str| {
        Request::post("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "username": username, "password": password }).to_string()))
            .unwrap()
    };

    let (status, headers, body) = app.send(login("amanda", "password1")).await;
    assert_eq!(status, StatusCode::OK);
    let cookie = headers[header::SET_COOKIE].to_str().unwrap();
    for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=43200"] {
        assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
    }
    let session: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session["user"]["username"], "amanda");
    assert_eq!(session["workspaces"][0]["id"], ws.to_string());
    assert_eq!(session["workspaces"][0]["role"], "owner");

    let session_cookie = cookie.split(';').next().unwrap();
    let (status, _, body) = app
        .send(
            Request::get("/api/auth/me")
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["user"]["id"], user);

    let (status, headers, _) = app.send(login("amanda", "wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(header::SET_COOKIE).is_none());

    let (status, _, _) = app.send(login("nobody", "password1")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let entries = app.audit(None).await;
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_ref()).collect();
    assert_eq!(actions, ["auth.login_failed", "auth.login_failed", "auth.login"]);
    assert_eq!(entries[0].actor_kind.as_ref(), "anonymous");
    assert_eq!(entries[0].details["username"], "nobody");
    assert_eq!(entries[2].actor_label.as_ref(), "amanda");
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn logout_clears_cookie_and_is_audited(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.user("amanda", "password1").await;

    let (status, headers, _) = app
        .send(
            Request::post("/api/auth/logout")
                .header(header::AUTHORIZATION, format!("Bearer {}", app.token(user)))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(headers[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
    assert_eq!(app.audit(None).await[0].action.as_ref(), "auth.logout");
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn workspaces_are_hidden_from_non_members(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.user("amanda", "password1").await;
    let mine = app.workspace("mine").await;
    let theirs = app.workspace("theirs").await;
    app.member(mine, user, Role::Member).await;
    let token = app.token(user);

    let (status, _) = app.call(Method::GET, &format!("/api/{mine}/sites/domains"), Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);

    for ws in [theirs.to_string(), Uuid::new_v4().to_string(), "not-a-uuid".into()] {
        let (status, _) = app.call(Method::GET, &format!("/api/{ws}/sites/domains"), Some(&token), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "workspace {ws}");
    }
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn mutations_are_audited_with_before_and_after(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.user("amanda", "password1").await;
    let ws = app.workspace("home").await;
    app.member(ws, user, Role::Member).await;
    let token = app.token(user);
    let base = format!("/api/{ws}");

    let (status, domain) = app
        .call(
            Method::POST,
            &format!("{base}/sites/domains"),
            Some(&token),
            Some(json!({ "scheme": "https", "domain": "wiki.org", "approved": null })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let domain_id = domain["id"].as_i64().unwrap();

    let (status, path) = app
        .call(
            Method::POST,
            &format!("{base}/sites/domains/{domain_id}/paths"),
            Some(&token),
            Some(json!({ "path": "/page", "approved": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let path_id = path["id"].as_i64().unwrap();

    let (status, _) = app
        .call(
            Method::PATCH,
            &format!("{base}/sites/domains/{domain_id}"),
            Some(&token),
            Some(json!({ "approved": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .call(Method::DELETE, &format!("{base}/sites/domains/{domain_id}/paths/{path_id}"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, video) = app
        .call(Method::POST, &format!("{base}/videos"), Some(&token), Some(json!({ "url": "https://youtu.be/a" })))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .call(Method::DELETE, &format!("{base}/videos/{}", video["id"]), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .call(Method::DELETE, &format!("{base}/sites/domains/{domain_id}"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let entries = app.audit(Some(ws)).await;
    let actions: Vec<&str> = entries.iter().rev().map(|entry| entry.action.as_ref()).collect();
    assert_eq!(
        actions,
        ["domain.create", "path.create", "domain.update", "path.delete", "video.create", "video.delete", "domain.delete"]
    );

    let by_action = |action: &str| entries.iter().find(|entry| entry.action.as_ref() == action).unwrap();

    let create = by_action("domain.create");
    assert!(create.details["before"].is_null());
    assert_eq!(create.details["after"], json!({ "scheme": "https", "domain": "wiki.org", "approved": null }));
    assert_eq!(create.actor_label.as_ref(), "amanda");
    assert_eq!(create.actor_kind.as_ref(), "user");
    assert_eq!(create.target_id.as_deref(), Some(domain_id.to_string().as_str()));

    let update = by_action("domain.update");
    assert!(update.details["before"]["approved"].is_null());
    assert_eq!(update.details["after"]["approved"], true);

    let path_delete = by_action("path.delete");
    assert_eq!(path_delete.details["domain"]["domain"], "wiki.org");
    assert_eq!(path_delete.details["before"], json!({ "path": "/page", "approved": true }));
    assert!(path_delete.details["after"].is_null());

    assert_eq!(by_action("domain.delete").details["before"]["approved"], true);
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn failed_mutations_leave_no_audit_entry(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.user("amanda", "password1").await;
    let ws = app.workspace("home").await;
    app.member(ws, user, Role::Member).await;
    let token = app.token(user);

    let (status, _) = app
        .call(Method::PATCH, &format!("/api/{ws}/sites/domains/999"), Some(&token), Some(json!({ "approved": true })))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app.call(Method::DELETE, &format!("/api/{ws}/videos/999"), Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    assert!(app.audit(Some(ws)).await.is_empty());
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn audit_log_is_owner_only(pool: PgPool) {
    let app = TestApp::new(pool);
    let owner = app.user("owner", "password1").await;
    let member = app.user("member", "password1").await;
    let ws = app.workspace("home").await;
    app.member(ws, owner, Role::Owner).await;
    app.member(ws, member, Role::Member).await;

    app.call(
        Method::POST,
        &format!("/api/{ws}/videos"),
        Some(&app.token(member)),
        Some(json!({ "url": "https://youtu.be/a" })),
    )
    .await;

    let (status, _) = app.call(Method::GET, &format!("/api/{ws}/audit"), Some(&app.token(member)), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, entries) = app
        .call(Method::GET, &format!("/api/{ws}/audit?actor=member"), Some(&app.token(owner)), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert_eq!(entries[0]["action"], "video.create");
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn devices_are_limited_and_revocable(pool: PgPool) {
    let app = TestApp::new(pool);
    let ws = app.workspace("home").await;

    let new = app.enroll(ws, "laptop").await;
    assert!(new.device.proxy_username.starts_with("dev-"));
    assert!(new.proxy_password.len() >= 32);

    let (status, _) = app.call(Method::GET, &format!("/api/{ws}/sites/domains"), Some(&new.token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app.call(Method::GET, "/api/auth/me", Some(&new.token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let icon = |token: &str| {
        Request::get("/static/icons/missing.png")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let (status, _, _) = app.send(icon(&new.token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let mut conn = app.pool.acquire().await.unwrap();
    enrollment::revoke(&mut conn, &Actor::cli(), new.device.id, None).await.unwrap().unwrap();
    drop(conn);

    let (status, _, _) = app.send(icon(&new.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let actions: Vec<_> = app.audit(Some(ws)).await.into_iter().map(|entry| entry.action).collect();
    assert_eq!(actions, ["device.revoke".into(), "device.create".into()]);
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn applications_list_sites_then_videos_with_etag(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.user("amanda", "password1").await;
    let ws = app.workspace("home").await;
    let other = app.workspace("other").await;
    app.member(ws, user, Role::Member).await;

    let mut conn = app.pool.acquire().await.unwrap();
    let c = &mut *conn;
    let wiki = sites::add_domain(c, ws, Scheme::Https, "en.wikipedia.org", None).await.unwrap();
    let page = sites::add_path(c, ws, wiki.id(), "/wiki/Page", true).await.unwrap().unwrap();
    let hello = sites::add_domain(c, ws, Scheme::Https, "hello.com", Some(true)).await.unwrap();
    sites::set_domain_metadata(c, wiki.id(), Some("Wikipedia"), Some("abc.png"), None).await.unwrap();
    sites::set_path_metadata(c, page.id(), Some("A Page"), None).await.unwrap();
    let video = videos::add_video(c, ws, "https://youtu.be/a", false).await.unwrap();
    let metadata = VideoMetadata { title: Some("A Video"), thumbnail: Some("def.png"), ..Default::default() };
    videos::set_metadata(c, video.id, &metadata, None).await.unwrap();
    sites::add_domain(c, other, Scheme::Https, "other.com", Some(true)).await.unwrap();
    drop(conn);

    let request = |token: &str, etag: Option<&str>| {
        let mut request = Request::get(format!("/api/{ws}/applications"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(etag) = etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        request.body(Body::empty()).unwrap()
    };

    let token = app.token(user);
    let (status, headers, body) = app.send(request(&token, None)).await;
    assert_eq!(status, StatusCode::OK);
    let apps: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        apps,
        json!([
            {
                "id": format!("chromium-path-{}", page.id()),
                "kind": "web",
                "name": "A Page",
                "url": "https://en.wikipedia.org/wiki/Page",
                "icon": "/static/icons/abc.png",
            },
            {
                "id": format!("chromium-domain-{}", hello.id()),
                "kind": "web",
                "name": "https://hello.com/",
                "url": "https://hello.com/",
                "icon": null,
            },
            {
                "id": format!("video-{}", video.id),
                "kind": "video",
                "name": "A Video",
                "url": "https://youtu.be/a",
                "icon": "/static/icons/def.png",
            },
        ])
    );

    let etag = headers[header::ETAG].to_str().unwrap().to_owned();
    let (status, headers, body) = app.send(request(&token, Some(&etag))).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert_eq!(headers[header::ETAG], etag.as_str());

    let device = app.enroll(ws, "laptop").await;
    let (status, headers, _) = app.send(request(&device.token, Some(&etag))).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED, "devices see the same list");
    assert_eq!(headers[header::ETAG], etag.as_str());

    let mut conn = app.pool.acquire().await.unwrap();
    sites::modify_domain(&mut conn, ws, hello.id(), Some(false)).await.unwrap();
    drop(conn);
    let (status, headers, _) = app.send(request(&token, Some(&etag))).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(headers[header::ETAG], etag.as_str());

    let foreign = app.enroll(other, "theirs").await;
    let (status, _, _) = app.send(request(&foreign.token, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn owners_manage_devices(pool: PgPool) {
    let app = TestApp::new(pool);
    let owner = app.user("owner", "password1").await;
    let member = app.user("member", "password1").await;
    let ws = app.workspace("home").await;
    let other = app.workspace("other").await;
    app.member(ws, owner, Role::Owner).await;
    app.member(ws, member, Role::Member).await;
    app.member(other, owner, Role::Owner).await;
    let owner_token = app.token(owner);
    let devices_url = format!("/api/{ws}/devices");

    let (status, _) = app
        .call(Method::POST, &devices_url, Some(&app.token(member)), Some(json!({ "name": "laptop" })))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app.call(Method::GET, &devices_url, Some(&app.token(member)), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app
        .call(Method::POST, &devices_url, Some(&owner_token), Some(json!({ "name": "  " })))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, created) = app
        .call(Method::POST, &devices_url, Some(&owner_token), Some(json!({ "name": " laptop " })))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["device"]["name"], "laptop");
    let device_id = created["device"]["id"].as_str().unwrap().to_owned();
    let device_token = created["token"].as_str().unwrap().to_owned();
    assert!(created["proxy_password"].as_str().unwrap().len() >= 32);

    let (status, _) = app
        .call(Method::GET, &format!("/api/{ws}/applications"), Some(&device_token), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, listed) = app.call(Method::GET, &devices_url, Some(&owner_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed[0]["id"], device_id.as_str());
    assert!(listed[0].get("proxy_password").is_none());

    let (status, _) = app
        .call(Method::DELETE, &format!("/api/{other}/devices/{device_id}"), Some(&owner_token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "revoking through another workspace");

    let (status, revoked) = app
        .call(Method::DELETE, &format!("{devices_url}/{device_id}"), Some(&owner_token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(revoked["revoked_at"].is_string());

    let (status, _) = app
        .call(Method::DELETE, &format!("{devices_url}/{device_id}"), Some(&owner_token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = app
        .call(Method::GET, &format!("/api/{ws}/applications"), Some(&device_token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let entries = app.audit(Some(ws)).await;
    assert_eq!(entries[0].action.as_ref(), "device.revoke");
    assert_eq!(entries[1].action.as_ref(), "device.create");
    assert!(entries.iter().all(|entry| entry.actor_label.as_ref() == "owner"));
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(
    addr: SocketAddr,
    workspace: WorkspaceId,
    token: &str,
    origin: Option<&str>,
) -> Result<Socket, tungstenite::Error> {
    let mut request = format!("ws://{addr}/api/{workspace}/events").into_client_request().unwrap();
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    if let Some(origin) = origin {
        request.headers_mut().insert(header::ORIGIN, origin.parse().unwrap());
    }
    tokio_tungstenite::connect_async(request).await.map(|(socket, _)| socket)
}

async fn next_event(socket: &mut Socket, wait: Duration) -> Option<Value> {
    loop {
        match tokio::time::timeout(wait, socket.next()).await.ok()?? {
            Ok(Message::Text(text)) => return Some(serde_json::from_str(&text).unwrap()),
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            other => panic!("unexpected websocket message: {other:?}"),
        }
    }
}

fn rejected_with(result: Result<Socket, tungstenite::Error>) -> StatusCode {
    match result {
        Err(tungstenite::Error::Http(response)) => response.status(),
        other => panic!("expected an HTTP rejection, got {:?}", other.map(|_| ())),
    }
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn events_push_debounced_application_changes(pool: PgPool) {
    let app = TestApp::new(pool);
    let ws = app.workspace("home").await;
    let other = app.workspace("other").await;
    let device = app.enroll(ws, "laptop").await;
    let addr = app.serve().await;

    let mut socket = connect(addr, ws, &device.token, None).await.unwrap();
    assert_eq!(next_event(&mut socket, Duration::from_secs(2)).await, Some(json!({ "type": "hello" })));

    let mut conn = app.pool.acquire().await.unwrap();
    for i in 0..5 {
        sites::add_domain(&mut conn, ws, Scheme::Https, &format!("site{i}.com"), Some(true)).await.unwrap();
    }
    assert_eq!(
        next_event(&mut socket, Duration::from_secs(2)).await,
        Some(json!({ "type": "applications_changed" }))
    );
    assert_eq!(next_event(&mut socket, Duration::from_millis(400)).await, None, "burst was debounced");

    sites::add_domain(&mut conn, other, Scheme::Https, "elsewhere.com", Some(true)).await.unwrap();
    assert_eq!(next_event(&mut socket, Duration::from_millis(400)).await, None, "other workspace");
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn events_require_access_to_the_workspace(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.user("amanda", "password1").await;
    let ws = app.workspace("home").await;
    let other = app.workspace("other").await;
    app.member(ws, user, Role::Member).await;
    let device = app.enroll(ws, "laptop").await;
    let addr = app.serve().await;

    let mut socket = connect(addr, ws, &app.token(user), Some(&format!("http://{addr}"))).await.unwrap();
    assert_eq!(next_event(&mut socket, Duration::from_secs(2)).await, Some(json!({ "type": "hello" })));

    let cross_site = connect(addr, ws, &app.token(user), Some("https://evil.example.com")).await;
    assert_eq!(rejected_with(cross_site), StatusCode::FORBIDDEN);

    assert_eq!(rejected_with(connect(addr, other, &device.token, None).await), StatusCode::NOT_FOUND);
    assert_eq!(rejected_with(connect(addr, other, &app.token(user), None).await), StatusCode::NOT_FOUND);
    assert_eq!(rejected_with(connect(addr, ws, "bogus", None).await), StatusCode::UNAUTHORIZED);
}

async fn create_invite(app: &TestApp, ws: WorkspaceId, token: &str, body: Value) -> (StatusCode, Value) {
    app.call(Method::POST, &format!("/api/{ws}/invites"), Some(token), Some(body)).await
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn invite_links_add_users_to_the_workspace(pool: PgPool) {
    let app = TestApp::new(pool);
    let owner = app.user("owner", "password1").await;
    let carol = app.user("carol", "password1").await;
    let dave = app.user("dave", "password1").await;
    let ws = app.workspace("Home").await;
    app.member(ws, owner, Role::Owner).await;
    let (owner_token, carol_token) = (app.token(owner), app.token(carol));

    let (status, invite) =
        create_invite(&app, ws, &owner_token, json!({ "max_uses": 1, "expires_in_days": 3 })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(invite["role"], "member");
    assert_eq!(invite["created_by"], "owner");
    let link = invite["token"].as_str().unwrap().to_owned();

    let (status, preview) = app.call(Method::GET, &format!("/api/invites/{link}"), Some(&carol_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preview["workspace"], json!({ "id": ws.to_string(), "name": "Home" }));
    assert_eq!(preview["role"], "member");
    assert_eq!(preview["invited_by"], "owner");
    assert!(preview["membership"].is_null());

    let (status, _) = app.call(Method::GET, &format!("/api/{ws}/sites/domains"), Some(&carol_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "not a member yet");

    let accept = format!("/api/invites/{link}/accept");
    let (status, joined) = app.call(Method::POST, &accept, Some(&carol_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(joined, json!({ "id": ws.to_string(), "name": "Home", "role": "member" }));

    let (status, _) = app.call(Method::GET, &format!("/api/{ws}/sites/domains"), Some(&carol_token), None).await;
    assert_eq!(status, StatusCode::OK);

    // The single use is spent, but Carol is told she's a member rather than that the link is dead.
    let (status, preview) = app.call(Method::GET, &format!("/api/invites/{link}"), Some(&carol_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preview["membership"], "member");
    let (status, _) = app.call(Method::POST, &accept, Some(&carol_token), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app.call(Method::POST, &accept, Some(&app.token(dave)), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "single-use invite already used");

    let entries = app.audit(Some(ws)).await;
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_ref()).collect();
    assert_eq!(actions, ["invite.accept", "invite.create"]);
    assert_eq!(entries[0].actor_label.as_ref(), "carol");
    assert_eq!(entries[0].details["role"], "member");
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn accepting_never_changes_an_existing_role(pool: PgPool) {
    let app = TestApp::new(pool);
    let owner = app.user("owner", "password1").await;
    let ws = app.workspace("Home").await;
    app.member(ws, owner, Role::Owner).await;
    let token = app.token(owner);

    let (_, invite) = create_invite(&app, ws, &token, json!({ "role": "member", "max_uses": 1 })).await;
    let link = invite["token"].as_str().unwrap();

    let (status, joined) = app.call(Method::POST, &format!("/api/invites/{link}/accept"), Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(joined["role"], "owner");

    let (_, invites) = app.call(Method::GET, &format!("/api/{ws}/invites"), Some(&token), None).await;
    assert_eq!(invites[0]["uses"], 0, "a member accepting doesn't use up the invite");
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn owners_manage_invites(pool: PgPool) {
    let app = TestApp::new(pool);
    let owner = app.user("owner", "password1").await;
    let member = app.user("member", "password1").await;
    let carol = app.user("carol", "password1").await;
    let ws = app.workspace("Home").await;
    app.member(ws, owner, Role::Owner).await;
    app.member(ws, member, Role::Member).await;
    let owner_token = app.token(owner);

    let (status, _) = create_invite(&app, ws, &app.token(member), json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app.call(Method::GET, &format!("/api/{ws}/invites"), Some(&app.token(member)), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    for body in [json!({ "expires_in_days": 0 }), json!({ "expires_in_days": 31 }), json!({ "max_uses": 0 })] {
        let (status, _) = create_invite(&app, ws, &owner_token, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }

    let (_, invite) = create_invite(&app, ws, &owner_token, json!({ "role": "owner" })).await;
    let id = invite["id"].as_str().unwrap().to_owned();
    let link = invite["token"].as_str().unwrap().to_owned();
    assert!(invite["max_uses"].is_null());

    let (_, listed) = app.call(Method::GET, &format!("/api/{ws}/invites"), Some(&owner_token), None).await;
    assert_eq!(listed[0]["id"], id.as_str());
    assert_eq!(listed[0]["token"], link.as_str(), "the same link can be copied again");

    let (status, _) = app.call(Method::DELETE, &format!("/api/{ws}/invites/{id}"), Some(&owner_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app.call(Method::DELETE, &format!("/api/{ws}/invites/{id}"), Some(&owner_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, listed) = app.call(Method::GET, &format!("/api/{ws}/invites"), Some(&owner_token), None).await;
    assert!(listed.as_array().unwrap().is_empty());

    let (status, _) = app
        .call(Method::POST, &format!("/api/invites/{link}/accept"), Some(&app.token(carol)), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "revoked");

    let actions: Vec<_> = app.audit(Some(ws)).await.into_iter().map(|entry| entry.action).collect();
    assert_eq!(actions, ["invite.revoke".into(), "invite.create".into()]);
}

#[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
async fn invite_tokens_are_not_credentials_and_cannot_be_forged(pool: PgPool) {
    let app = TestApp::new(pool);
    let owner = app.user("owner", "password1").await;
    let carol = app.user("carol", "password1").await;
    let ws = app.workspace("Home").await;
    app.member(ws, owner, Role::Owner).await;
    let carol_token = app.token(carol);

    let (_, invite) = create_invite(&app, ws, &app.token(owner), json!({})).await;
    let link = invite["token"].as_str().unwrap().to_owned();

    let (status, _) = app.call(Method::GET, "/api/auth/me", Some(&link), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "an invite is not a session");

    let mut tampered = link.clone();
    tampered.pop();
    let forged = Keys::from_base64(&STANDARD.encode([8u8; 32]))
        .unwrap()
        .issue_invite(invite["id"].as_str().unwrap().parse().unwrap(), ws, chrono::Utc::now() + chrono::TimeDelta::days(1))
        .unwrap();
    for bad in [tampered.as_str(), forged.as_ref(), app.token(owner).as_ref(), "nonsense"] {
        let (status, _) = app.call(Method::POST, &format!("/api/invites/{bad}/accept"), Some(&carol_token), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    let device = app.enroll(ws, "laptop").await;
    let (status, _) = app
        .call(Method::POST, &format!("/api/invites/{link}/accept"), Some(&device.token), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "devices can't join workspaces");

    let (status, headers, _) = app
        .send(Request::get(format!("/invite/{link}")).body(Body::empty()).unwrap())
        .await;
    assert!(status.is_redirection());
    let location = headers[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with("/login?next=%2Finvite%2F"), "{location}");
}
