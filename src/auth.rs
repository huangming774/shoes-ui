use axum::http::{header, HeaderMap};
use chrono::Utc;
use parking_lot::Mutex;
use std::collections::HashMap;

use crate::crypto_util::generate_random_alnum;

pub const SESSION_COOKIE_NAME: &str = "shoes_panel_session";

pub struct SessionStore {
    // token -> (username, expires_at_ms)
    sessions: Mutex<HashMap<String, (String, i64)>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl SessionStore {
    pub fn create_session(&self, username: &str, ttl_hours: u64) -> String {
        let now = Utc::now().timestamp_millis();
        let lifetime_ms = ttl_hours.max(1).saturating_mul(3_600_000);
        let expires = now.saturating_add(i64::try_from(lifetime_ms).unwrap_or(i64::MAX));
        let token = generate_random_alnum(40);
        let mut guard = self.sessions.lock();
        guard.retain(|_, (_, exp)| *exp > now);
        guard.insert(token.clone(), (username.to_string(), expires));
        token
    }

    pub fn validate(&self, token: &str) -> Option<String> {
        if token.is_empty() {
            return None;
        }
        let now = Utc::now().timestamp_millis();
        let mut guard = self.sessions.lock();
        if let Some((user, exp)) = guard.get(token) {
            if *exp > now {
                return Some(user.clone());
            }
            guard.remove(token);
        }
        None
    }

    pub fn revoke(&self, token: &str) {
        self.sessions.lock().remove(token);
    }

    pub fn revoke_all(&self) {
        self.sessions.lock().clear();
    }
}

pub fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(auth_val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tok) = auth_val.strip_prefix("Bearer ") {
            let t = tok.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie_hdr.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k.trim() == SESSION_COOKIE_NAME && !v.trim().is_empty() {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}
