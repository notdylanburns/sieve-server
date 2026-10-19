use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, header};
use ipnetwork::IpNetwork;

const MAX_USER_AGENT_LEN: usize = 512;

/// Where a request came from, for the audit log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClientInfo {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<Box<str>>,
}

impl ClientInfo {
    pub fn from_request<B>(request: &Request<B>, trusted_proxies: &[IpNetwork]) -> Self {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());

        Self {
            ip: peer.map(|peer| client_ip(peer, request.headers(), trusted_proxies)),
            user_agent: request
                .headers()
                .get(header::USER_AGENT)
                .and_then(|agent| agent.to_str().ok())
                .map(|agent| truncate(agent, MAX_USER_AGENT_LEN).into()),
        }
    }
}

/// X-Forwarded-For is only believed for hops added by trusted proxies, walking right to left.
fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpNetwork]) -> IpAddr {
    let trusted = |ip: &IpAddr| trusted_proxies.iter().any(|net| net.contains(*ip));

    if !trusted(&peer) {
        return peer;
    }

    let hops = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect::<Vec<_>>();

    let mut client = peer;
    for hop in hops.into_iter().rev() {
        let Ok(ip) = hop.parse::<IpAddr>() else {
            break;
        };
        client = ip;
        if !trusted(&ip) {
            break;
        }
    }
    client
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((end, _)) => &s[..end],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(xff: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        headers
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forwarded_for_is_ignored_from_untrusted_peers() {
        let trusted = ["172.18.0.0/16".parse().unwrap()];
        assert_eq!(client_ip(ip("203.0.113.5"), &headers("1.2.3.4"), &trusted), ip("203.0.113.5"));
        assert_eq!(client_ip(ip("172.18.0.2"), &headers("1.2.3.4"), &[]), ip("172.18.0.2"));
    }

    #[test]
    fn forwarded_for_from_trusted_proxy_uses_last_untrusted_hop() {
        let trusted = ["172.18.0.0/16".parse().unwrap()];
        let peer = ip("172.18.0.2");
        assert_eq!(client_ip(peer, &headers("1.2.3.4"), &trusted), ip("1.2.3.4"));
        assert_eq!(client_ip(peer, &headers("6.6.6.6, 1.2.3.4"), &trusted), ip("1.2.3.4"));
        assert_eq!(client_ip(peer, &headers("1.2.3.4, 172.18.0.9"), &trusted), ip("1.2.3.4"));
        assert_eq!(client_ip(peer, &headers("garbage"), &trusted), peer);
        assert_eq!(client_ip(peer, &HeaderMap::new(), &trusted), peer);
    }

    #[test]
    fn truncates_on_char_boundaries() {
        assert_eq!(truncate("héllo", 2), "hé");
        assert_eq!(truncate("hi", 10), "hi");
    }
}
