use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Extension;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::http::{HeaderMap, header};
use axum::response::Response;
use log::{debug, error, info, warn};
use sieve_common::database::{WorkspaceId, devices, notify, workspaces};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Notify, broadcast};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::auth::Principal;
use crate::error::ApiError;
use crate::state::AppState;
use crate::workspace::ClientWorkspace;

pub(crate) const DEBOUNCE: Duration = Duration::from_secs(1);
const PING_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const CHANNEL_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Event {
    Hello,
    ApplicationsChanged,
}

/// Fans database notifications out to the sockets subscribed to each workspace.
pub(crate) struct Hub {
    channels: Mutex<HashMap<WorkspaceId, broadcast::Sender<Event>>>,
    pending: Mutex<HashSet<WorkspaceId>>,
    debounce: Duration,
}

impl Hub {
    pub fn new(debounce: Duration) -> Arc<Self> {
        Arc::new(Self {
            channels: Mutex::default(),
            pending: Mutex::default(),
            debounce,
        })
    }

    pub fn subscribe(&self, workspace: WorkspaceId) -> broadcast::Receiver<Event> {
        let mut channels = self.channels.lock().expect("hub mutex poisoned");
        channels
            .entry(workspace)
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe()
    }

    fn publish(&self, workspace: WorkspaceId, event: Event) {
        let mut channels = self.channels.lock().expect("hub mutex poisoned");
        if let Some(sender) = channels.get(&workspace)
            && sender.send(event).is_err()
        {
            channels.remove(&workspace);
        }
    }

    /// Sends `applications_changed` once the burst of changes for this workspace has settled.
    pub fn notify(self: &Arc<Self>, workspace: WorkspaceId) {
        if !self.pending.lock().expect("hub mutex poisoned").insert(workspace) {
            return;
        }

        let hub = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(hub.debounce).await;
            hub.pending.lock().expect("hub mutex poisoned").remove(&workspace);
            hub.publish(workspace, Event::ApplicationsChanged);
        });
    }

    fn notify_all(self: &Arc<Self>) {
        let workspaces: Vec<_> = self
            .channels
            .lock()
            .expect("hub mutex poisoned")
            .keys()
            .copied()
            .collect();
        for workspace in workspaces {
            self.notify(workspace);
        }
    }
}

/// Listens for `sieve_applications` for the life of the process, reconnecting as needed.
/// The returned `Notify` is signalled once the first `LISTEN` succeeds.
pub(crate) fn spawn_listener(pool: PgPool, hub: Arc<Hub>) -> (Arc<Notify>, JoinHandle<()>) {
    let ready = Arc::new(Notify::new());
    let signal = Arc::clone(&ready);

    let task = tokio::spawn(async move {
        loop {
            let mut listener = match PgListener::connect_with(&pool).await {
                Ok(listener) => listener,
                Err(e) => {
                    error!("failed to connect notification listener: {e}");
                    tokio::time::sleep(RECONNECT_DELAY).await;
                    continue;
                }
            };

            if let Err(e) = listener.listen(notify::APPLICATIONS).await {
                error!("failed to listen for {}: {e}", notify::APPLICATIONS);
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }

            info!("listening for {}", notify::APPLICATIONS);
            signal.notify_one();
            // Changes made while disconnected were missed.
            hub.notify_all();

            loop {
                match listener.try_recv().await {
                    Ok(Some(notification)) => match notification.payload().parse() {
                        Ok(workspace) => hub.notify(workspace),
                        Err(e) => warn!("ignoring notification '{}': {e}", notification.payload()),
                    },
                    // try_recv reconnects on the next call; anything sent in between is lost.
                    Ok(None) => {
                        warn!("notification listener lost its connection");
                        hub.notify_all();
                    }
                    Err(e) => {
                        error!("notification listener failed: {e}");
                        break;
                    }
                }
            }

            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    });

    (ready, task)
}

/// Browsers send Origin on WebSocket handshakes and don't apply CORS to them, so check it here.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|origin| origin.to_str().ok()) else {
        return true;
    };
    let host = headers.get(header::HOST).and_then(|host| host.to_str().ok());

    url::Url::parse(origin)
        .ok()
        .and_then(|origin| {
            let authority = match origin.port() {
                Some(port) => format!("{}:{port}", origin.host_str()?),
                None => origin.host_str()?.to_owned(),
            };
            Some(Some(authority.as_str()) == host)
        })
        .unwrap_or(false)
}

pub(crate) async fn get(
    State(state): State<AppState>,
    ClientWorkspace(workspace): ClientWorkspace,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    if !same_origin(&headers) {
        return Err(ApiError::Forbidden);
    }

    let events = state.events.subscribe(workspace);
    Ok(upgrade.on_upgrade(move |socket| serve(socket, events, state, workspace, principal)))
}

async fn send(socket: &mut WebSocket, event: Event) -> Result<(), axum::Error> {
    let json = serde_json::to_string(&event).expect("events always serialise");
    socket.send(Message::Text(json.into())).await
}

/// Revocation and membership changes take effect on open sockets at the next ping.
async fn still_authorized(state: &AppState, workspace: WorkspaceId, principal: &Principal) -> bool {
    let Ok(mut conn) = state.conn().await else {
        return true;
    };

    let result = match principal {
        Principal::Device(device) => devices::get_active(&mut conn, device.id)
            .await
            .map(|device| device.is_some()),
        Principal::User(user) => workspaces::member_role(&mut conn, workspace, user.id)
            .await
            .map(|role| role.is_some()),
    };

    result.unwrap_or_else(|e| {
        warn!("failed to recheck socket authorisation: {e}");
        true
    })
}

async fn serve(
    mut socket: WebSocket,
    mut events: broadcast::Receiver<Event>,
    state: AppState,
    workspace: WorkspaceId,
    principal: Principal,
) {
    if send(&mut socket, Event::Hello).await.is_err() {
        return;
    }

    let mut ping = tokio::time::interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut awaiting_pong = false;

    loop {
        tokio::select! {
            event = events.recv() => {
                let event = match event {
                    Ok(event) => event,
                    Err(RecvError::Lagged(_)) => Event::ApplicationsChanged,
                    Err(RecvError::Closed) => break,
                };
                if send(&mut socket, event).await.is_err() {
                    break;
                }
            }
            message = socket.recv() => match message {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => awaiting_pong = false,
            },
            _ = ping.tick() => {
                if awaiting_pong {
                    debug!("dropping unresponsive socket for {workspace}");
                    break;
                }
                if !still_authorized(&state, workspace, &principal).await {
                    let close = CloseFrame { code: close_code::POLICY, reason: "unauthorized".into() };
                    let _ = socket.send(Message::Close(Some(close))).await;
                    break;
                }
                if socket.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
                awaiting_pong = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use uuid::Uuid;

    #[test]
    fn origin_must_match_host_when_present() {
        let mut headers = HeaderMap::new();
        assert!(same_origin(&headers));

        headers.insert(header::HOST, HeaderValue::from_static("sieve.example.com"));
        headers.insert(header::ORIGIN, HeaderValue::from_static("https://sieve.example.com"));
        assert!(same_origin(&headers));

        headers.insert(header::ORIGIN, HeaderValue::from_static("https://evil.example.com"));
        assert!(!same_origin(&headers));

        headers.insert(header::HOST, HeaderValue::from_static("localhost:8080"));
        headers.insert(header::ORIGIN, HeaderValue::from_static("http://localhost:8080"));
        assert!(same_origin(&headers));

        headers.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert!(!same_origin(&headers));
    }

    #[tokio::test]
    async fn notifications_are_debounced_per_workspace() {
        let hub = Hub::new(Duration::from_millis(50));
        let a = WorkspaceId(Uuid::new_v4());
        let b = WorkspaceId(Uuid::new_v4());
        let mut rx_a = hub.subscribe(a);
        let mut rx_b = hub.subscribe(b);

        for _ in 0..5 {
            hub.notify(a);
        }

        let event = tokio::time::timeout(Duration::from_secs(1), rx_a.recv()).await;
        assert_eq!(event.unwrap().unwrap(), Event::ApplicationsChanged);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(rx_a.try_recv().is_err());
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn unsubscribed_workspaces_are_forgotten() {
        let hub = Hub::new(Duration::ZERO);
        let ws = WorkspaceId(Uuid::new_v4());
        drop(hub.subscribe(ws));

        hub.publish(ws, Event::ApplicationsChanged);
        assert!(hub.channels.lock().unwrap().is_empty());
    }
}
