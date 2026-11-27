use axum::http::{header, HeaderMap};
use chrono::Utc;
use parking_lot::Mutex;
use std::collections::HashMap;

use crate::crypto_util::generate_random_alnum;

pub const SESSION_COOKIE_NAME: &str = "shoes_panel_session";

const MAX_LOGIN_FAILURES: u32 = 8;
const FAILURE_WINDOW_MS: i64 = 5 * 60 * 1000;
const LOCKOUT_DURATION_MS: i64 = 5 * 60 * 1000;

/// In-memory brute-force protection for public-facing panel login endpoints.
#[derive(Default)]
pub struct LoginGuard {
    state: Mutex<LoginGuardState>,
}

#[derive(Default)]
struct LoginGuardState {
    failures: u32,
    first_failure_ms: i64,
    locked_until_ms: i64,
}

impl LoginGuard {
    pub fn check_locked(&self) -> Option<u64> {
        let now = Utc::now().timestamp_millis();
        let mut guard = self.state.lock();
        if guard.locked_until_ms > now {
            let secs = ((guard.locked_until_ms - now) + 999) / 1000;
            return Some(secs.max(1) as u64);
        }
        if guard.locked_until_ms > 0 && guard.locked_until_ms <= now {
            *guard = LoginGuardState::default();
        }
        None
    }

    pub fn record_failure(&self) -> Option<u64> {
        let now = Utc::now().timestamp_millis();
        let mut guard = self.state.lock();
        if guard.first_failure_ms == 0 || now - guard.first_failure_ms > FAILURE_WINDOW_MS {
            guard.failures = 1;
            guard.first_failure_ms = now;
            guard.locked_until_ms = 0;
            return None;
        }
        guard.failures += 1;
        if guard.failures >= MAX_LOGIN_FAILURES {
            guard.locked_until_ms = now + LOCKOUT_DURATION_MS;
            return Some((LOCKOUT_DURATION_MS / 1000) as u64);
        }
        None
    }

    pub fn record_success(&self) {
        *self.state.lock() = LoginGuardState::default();
    }
}

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

pub fn extract_cluster_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(tok) = headers
        .get("x-cluster-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(tok.to_string());
    }
    extract_token_from_headers(headers)
}
