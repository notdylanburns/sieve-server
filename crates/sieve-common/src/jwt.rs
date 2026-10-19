use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::config;
use crate::database::WorkspaceId;

pub const SESSION_TTL: TimeDelta = TimeDelta::hours(12);
pub const OAUTH_TTL: TimeDelta = TimeDelta::minutes(10);
const MIN_SECRET_BYTES: usize = 32;
const LEEWAY_SECONDS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Claims {
    User { sub: Box<str>, iat: i64, exp: i64 },
    /// Device tokens never expire; revocation is checked against the database instead.
    Device { sub: Box<str>, ws: WorkspaceId, iat: i64 },
    /// Names an invite row, which stays authoritative for revocation and use limits.
    /// Never accepted as a credential.
    Invite { sub: Box<str>, ws: WorkspaceId, exp: i64 },
    /// A Google sign-in in progress, held in a cookie while the browser is away at Google.
    /// Never accepted as a credential.
    OAuth { state: Box<str>, verifier: Box<str>, next: Box<str>, exp: i64 },
}

/// What a Google sign-in needs to remember while the browser is away at Google.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthState {
    pub state: Box<str>,
    pub verifier: Box<str>,
    /// Where to send the user once they're signed in.
    pub next: Box<str>,
}

pub struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
}

impl Keys {
    pub fn from_base64(secret: &str) -> Result<Self, Box<str>> {
        let secret = STANDARD
            .decode(secret.trim())
            .map_err(|e| format!("not valid base64: {e}"))?;

        if secret.len() < MIN_SECRET_BYTES {
            return Err(format!("must decode to at least {MIN_SECRET_BYTES} bytes").into());
        }

        // exp is optional (device tokens) and checked by hand for user tokens.
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;

        Ok(Self {
            encoding: EncodingKey::from_secret(&secret),
            decoding: DecodingKey::from_secret(&secret),
            validation,
        })
    }

    pub fn from_env() -> Result<Self, config::Error> {
        Self::from_base64(&config::var("JWT_SECRET")?)
            .map_err(|e| config::Error::Invalid("JWT_SECRET", e.into_string()))
    }

    pub fn issue_user(&self, user_id: i64) -> jsonwebtoken::errors::Result<Box<str>> {
        let now = Utc::now();
        self.encode(&Claims::User {
            sub: user_id.to_string().into(),
            iat: now.timestamp(),
            exp: (now + SESSION_TTL).timestamp(),
        })
    }

    pub fn issue_device(
        &self,
        device_id: Uuid,
        workspace: WorkspaceId,
    ) -> jsonwebtoken::errors::Result<Box<str>> {
        self.encode(&Claims::Device {
            sub: device_id.to_string().into(),
            ws: workspace,
            iat: Utc::now().timestamp(),
        })
    }

    /// Deterministic for a given invite, so owners can copy the same link again later.
    pub fn issue_invite(
        &self,
        invite_id: Uuid,
        workspace: WorkspaceId,
        expires_at: DateTime<Utc>,
    ) -> jsonwebtoken::errors::Result<Box<str>> {
        self.encode(&Claims::Invite {
            sub: invite_id.to_string().into(),
            ws: workspace,
            exp: expires_at.timestamp(),
        })
    }

    /// Returns the invite id and workspace for a genuine, unexpired invite token, and None for
    /// anything else, including session and device tokens.
    pub fn verify_invite(&self, token: &str) -> Option<(Uuid, WorkspaceId)> {
        match self.verify(token)? {
            Claims::Invite { sub, ws, .. } => Some((sub.parse().ok()?, ws)),
            _ => None,
        }
    }

    pub fn issue_oauth(&self, oauth: &OAuthState) -> jsonwebtoken::errors::Result<Box<str>> {
        self.encode(&Claims::OAuth {
            state: oauth.state.clone(),
            verifier: oauth.verifier.clone(),
            next: oauth.next.clone(),
            exp: (Utc::now() + OAUTH_TTL).timestamp(),
        })
    }

    /// Returns None for anything but a genuine, unexpired sign-in token.
    pub fn verify_oauth(&self, token: &str) -> Option<OAuthState> {
        match self.verify(token)? {
            Claims::OAuth { state, verifier, next, .. } => Some(OAuthState { state, verifier, next }),
            _ => None,
        }
    }

    fn encode(&self, claims: &Claims) -> jsonwebtoken::errors::Result<Box<str>> {
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), claims, &self.encoding)
            .map(String::into_boxed_str)
    }

    /// Returns None for tokens that are malformed, wrongly signed or expired.
    pub fn verify(&self, token: &str) -> Option<Claims> {
        let claims = jsonwebtoken::decode::<Claims>(token, &self.decoding, &self.validation)
            .ok()?
            .claims;

        let expired = |exp: i64| exp + LEEWAY_SECONDS < Utc::now().timestamp();
        match claims {
            Claims::User { exp, .. } | Claims::Invite { exp, .. } | Claims::OAuth { exp, .. }
                if expired(exp) =>
            {
                None
            }
            claims => Some(claims),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> Keys {
        Keys::from_base64(&STANDARD.encode([7u8; MIN_SECRET_BYTES])).unwrap()
    }

    #[test]
    fn rejects_short_or_invalid_secrets() {
        assert!(Keys::from_base64("not base64!").is_err());
        assert!(Keys::from_base64(&STANDARD.encode([1u8; 16])).is_err());
    }

    #[test]
    fn round_trips_user_and_device_tokens() {
        let keys = test_keys();
        let user = keys.issue_user(42).unwrap();
        assert!(matches!(keys.verify(&user), Some(Claims::User { sub, .. }) if sub.as_ref() == "42"));

        let ws = WorkspaceId(Uuid::new_v4());
        let device_id = Uuid::new_v4();
        let device = keys.issue_device(device_id, ws).unwrap();
        assert!(matches!(
            keys.verify(&device),
            Some(Claims::Device { sub, ws: claim_ws, .. })
                if sub.as_ref() == device_id.to_string() && claim_ws == ws
        ));
    }

    #[test]
    fn rejects_expired_tampered_and_foreign_tokens() {
        let keys = test_keys();
        let expired = keys
            .encode(&Claims::User { sub: "1".into(), iat: 0, exp: 1 })
            .unwrap();
        assert_eq!(keys.verify(&expired), None);

        let token = keys.issue_user(1).unwrap();
        let mut tampered = token.to_string();
        tampered.pop();
        assert_eq!(keys.verify(&tampered), None);

        let other = Keys::from_base64(&STANDARD.encode([9u8; MIN_SECRET_BYTES])).unwrap();
        assert_eq!(other.verify(&token), None);
    }

    #[test]
    fn invite_tokens_are_stable_and_only_valid_as_invites() {
        let keys = test_keys();
        let ws = WorkspaceId(Uuid::new_v4());
        let id = Uuid::new_v4();
        let expires = Utc::now() + TimeDelta::days(7);

        let token = keys.issue_invite(id, ws, expires).unwrap();
        assert_eq!(keys.issue_invite(id, ws, expires).unwrap(), token);
        assert_eq!(keys.verify_invite(&token), Some((id, ws)));

        assert_eq!(keys.verify_invite(&keys.issue_user(1).unwrap()), None);
        assert_eq!(keys.verify_invite(&keys.issue_device(id, ws).unwrap()), None);

        let expired = keys.issue_invite(id, ws, Utc::now() - TimeDelta::hours(1)).unwrap();
        assert_eq!(keys.verify_invite(&expired), None);

        let other = Keys::from_base64(&STANDARD.encode([9u8; MIN_SECRET_BYTES])).unwrap();
        assert_eq!(other.verify_invite(&token), None);
    }

    #[test]
    fn oauth_tokens_round_trip_and_are_only_valid_as_oauth() {
        let keys = test_keys();
        let oauth = OAuthState { state: "s".into(), verifier: "v".into(), next: "/w/1".into() };

        let token = keys.issue_oauth(&oauth).unwrap();
        assert_eq!(keys.verify_oauth(&token), Some(oauth));
        assert_eq!(keys.verify_oauth(&keys.issue_user(1).unwrap()), None);

        let expired = keys
            .encode(&Claims::OAuth { state: "s".into(), verifier: "v".into(), next: "/".into(), exp: 1 })
            .unwrap();
        assert_eq!(keys.verify_oauth(&expired), None);
    }
}
