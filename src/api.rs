use axum::{
    body::Body,
    extract::{Multipart, Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::acme_util::{
    export_acme_state_for_panel, fetch_acme_directory_meta, inspect_certificate_runtime,
    issue_shortlived_ip_cert, reload_panel_https_if_matching, renew_ip_certificate_record,
    sanitize_cert_filename, validate_cert_key_pair, write_cert_and_key_atomic, CertRuntimeStatus,
};
use crate::auth::{extract_token_from_headers, SESSION_COOKIE_NAME};
use crate::crypto_util::{
    generate_random_alnum, generate_reality_keypair, generate_self_signed_cert,
    generate_short_id, generate_ss2022_password, generate_uuid,
};
use crate::db::default_client_for_inbound;
use crate::models::{
    CertificateRecord, ClientRecord, Inbound, OutboundGroupRecord, PanelSettings,
    RoutingRuleRecord, SubscriptionRecord, DEFAULT_LETSENCRYPT_DIR, DEFAULT_LETSENCRYPT_TOS,
};
use crate::ops_util::{
    backups_dir, build_backup_caption, check_github_updates, create_local_backup,
    list_local_backups, sanitize_backup_filename, schedule_panel_restart, send_backup_to_telegram,
    upgrade_panel_binary, upgrade_shoes_binary,
};
use crate::state::{is_loopback_or_unspecified_host, AppState};
use crate::sub_gen::{
    build_client_share_info, generate_subscription_with_certs, SubFormat,
};
use crate::yaml_gen::{build_shoes_yaml, normalize_acme_domains};

#[derive(RustEmbed)]
#[folder = "web/dist"]
struct WebAssets;

type ApiResult<T = Value> = Result<Json<T>, (StatusCode, Json<Value>)>;

fn ok_json(data: impl serde::Serialize) -> ApiResult {
    Ok(Json(json!({ "ok": true, "data": data })))
}

fn err_json(status: StatusCode, msg: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "ok": false, "error": msg.to_string() })))
}

fn bad_req(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    err_json(StatusCode::BAD_REQUEST, e)
}

fn internal_err(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    err_json(StatusCode::INTERNAL_SERVER_ERROR, e)
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if let Some(tok) = extract_token_from_headers(req.headers()) {
        if state.sessions.validate(&tok).is_some() {
            return Ok(next.run(req).await);
        }
    }
    Err(err_json(StatusCode::UNAUTHORIZED, "Unauthorized"))
}

pub fn build_inner_router(state: Arc<AppState>) -> Router {
    let protected_api = Router::new()
        // Dashboard & Shoes service control
        .route("/status", get(api_status))
        .route("/traffic/daily", get(api_daily_traffic))
        .route("/status/history", get(api_core_history))
        .route("/shoes/start", post(api_shoes_start))
        .route("/shoes/stop", post(api_shoes_stop))
        .route("/shoes/restart", post(api_shoes_restart))
        .route("/shoes/reload", post(api_shoes_reload))
        .route("/shoes/logs", get(api_shoes_logs))
        .route("/shoes/logs/clear", post(api_shoes_logs_clear))
        .route("/shoes/config-preview", get(api_shoes_config_preview))
        // Clash API proxy endpoints
        .route(
            "/clash/connections",
            get(api_clash_connections).delete(api_clash_close_all_connections),
        )
        .route(
            "/clash/connections/{id}",
            delete(api_clash_close_connection),
        )
        .route("/clash/proxies", get(api_clash_proxies))
        .route("/clash/proxies/{group}", put(api_clash_select_proxy))
        .route("/clash/delay", get(api_clash_delay))
        // Inbounds & Clients (Two-Layer Model)
        .route("/inbounds", get(api_list_inbounds).post(api_create_inbound))
        .route(
            "/inbounds/reset-all-traffic",
            post(api_reset_all_inbound_traffic),
        )
        .route(
            "/inbounds/{id}",
            put(api_update_inbound).delete(api_delete_inbound),
        )
        .route("/inbounds/{id}/toggle", post(api_toggle_inbound))
        .route("/inbounds/{id}/clone", post(api_clone_inbound))
        .route("/inbounds/{id}/reset-traffic", post(api_reset_inbound_traffic))
        .route("/inbounds/{id}/share", get(api_inbound_share))
        .route("/inbounds/{id}/clients", post(api_add_client))
        .route(
            "/clients/{client_id}",
            put(api_update_client).delete(api_delete_client),
        )
        .route("/next-port", get(api_next_port))
        // Keygen utilities
        .route("/keygen/uuid", get(api_keygen_uuid))
        .route("/keygen/reality", get(api_keygen_reality))
        .route("/keygen/ss2022", get(api_keygen_ss2022))
        .route("/keygen/random", get(api_keygen_random))
        // Certificates
        .route(
            "/certificates",
            get(api_list_certs).post(api_save_cert),
        )
        .route("/certificates/acme-meta", get(api_acme_meta))
        .route("/certificates/upload", post(api_upload_cert))
        .route("/certificates/self-signed", post(api_self_signed_cert))
        .route("/certificates/issue-ip", post(api_issue_ip_cert))
        .route("/certificates/{id}/renew", post(api_renew_cert))
        .route(
            "/certificates/{id}/apply-panel-https",
            post(api_apply_panel_https),
        )
        .route("/certificates/{id}", delete(api_delete_cert))
        // Outbound Groups & Routing Rules
        .route(
            "/outbound-groups",
            get(api_list_outbound_groups).post(api_save_outbound_group),
        )
        .route("/outbound-groups/{id}", delete(api_delete_outbound_group))
        .route(
            "/routing-rules",
            get(api_list_routing_rules).post(api_save_routing_rule),
        )
        .route("/routing-rules/{id}", delete(api_delete_routing_rule))
        // Subscriptions
        .route(
            "/subscriptions",
            get(api_list_subscriptions).post(api_save_subscription),
        )
        .route("/subscriptions/{id}/rotate", post(api_rotate_subscription))
        .route("/subscriptions/{id}", delete(api_delete_subscription))
        // Panel Settings & Account
        .route("/settings", get(api_get_settings).put(api_save_settings))
        .route("/settings/public-host", post(api_set_public_host))
        .route("/settings/password", post(api_change_password))
        .route("/settings/backup-db", get(api_backup_db))
        .route("/settings/restore-db", post(api_restore_db))
        .route("/settings/backups", get(api_list_backups))
        .route("/settings/backup-now", post(api_backup_now))
        .route("/settings/backup-tg-test", post(api_backup_tg_test))
        .route(
            "/settings/backups/{filename}",
            get(api_download_local_backup).delete(api_delete_local_backup),
        )
        .route(
            "/settings/backups/{filename}/restore",
            post(api_restore_local_backup),
        )
        // Panel Restart & GitHub Online Updates
        .route("/panel/restart", post(api_panel_restart))
        .route("/system/updates", get(api_check_updates))
        .route("/system/upgrade-panel", post(api_upgrade_panel))
        .route("/system/upgrade-shoes", post(api_upgrade_shoes))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let public_api = Router::new()
        .route("/auth/login", post(api_login))
        .route("/auth/logout", post(api_logout))
        .route("/auth/me", get(api_me));

    Router::new()
        .nest("/api", public_api.merge(protected_api))
        .route("/sub/{token}", get(public_subscription_handler))
        .fallback(serve_spa)
        .with_state(state)
}

fn strip_host_port(raw: &str) -> String {
    let first = raw.split(',').next().unwrap_or("").trim();
    if let Some(rest) = first.strip_prefix('[') {
        if let Some((ipv6, _)) = rest.split_once(']') {
            return ipv6.to_string();
        }
    }
    if let Some((h, _)) = first.rsplit_once(':') {
        if !h.contains(':') {
            return h.to_string();
        }
    }
    first.to_string()
}

fn resolve_share_host(
    state: &AppState,
    settings: &PanelSettings,
    headers: &HeaderMap,
    query_host: Option<&str>,
) -> String {
    if let Some(h) = query_host {
        let t = h.trim();
        if !t.is_empty() && !is_loopback_or_unspecified_host(t) {
            return t.to_string();
        }
    }
    let configured = settings.public_host.trim();
    if !configured.is_empty() && !is_loopback_or_unspecified_host(configured) {
        return strip_host_port(configured);
    }
    // Check reverse-proxy X-Forwarded-Host before Host header
    if let Some(xfh) = headers.get("x-forwarded-host").and_then(|v| v.to_str().ok()) {
        let h = strip_host_port(xfh);
        if !h.is_empty() && !is_loopback_or_unspecified_host(&h) {
            return h;
        }
    }
    let host_from_hdr = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_host_port)
        .unwrap_or_default();
    if !host_from_hdr.is_empty() && !is_loopback_or_unspecified_host(&host_from_hdr) {
        return host_from_hdr;
    }
    // If accessed via 127.0.0.1 / SSH tunnel / Nginx proxy_pass, prefer detected server public IP!
    let detected = state.get_detected_public_ip();
    if !detected.is_empty() {
        return detected;
    }
    if !configured.is_empty() && configured != "0.0.0.0" {
        return strip_host_port(configured);
    }
    if !host_from_hdr.is_empty() && host_from_hdr != "0.0.0.0" {
        return host_from_hdr;
    }
    "127.0.0.1".to_string()
}

// ==================== Auth Handlers ====================

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn api_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginReq>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if let Some(wait_secs) = state.login_guard.check_locked() {
        return Err(err_json(
            StatusCode::TOO_MANY_REQUESTS,
            format!("Too many failed login attempts. Try again in {wait_secs}s."),
        ));
    }
    let valid = state
        .db
        .verify_user(req.username.trim(), &req.password)
        .map_err(internal_err)?;
    if !valid {
        if let Some(lock_secs) = state.login_guard.record_failure() {
            return Err(err_json(
                StatusCode::TOO_MANY_REQUESTS,
                format!("Too many failed login attempts. Locked for {lock_secs}s."),
            ));
        }
        return Err(err_json(
            StatusCode::UNAUTHORIZED,
            "Invalid username or password",
        ));
    }
    state.login_guard.record_success();
    let ttl = state
        .db
        .get_settings()
        .map(|s| s.session_ttl_hours)
        .unwrap_or(168);
    let token = state.sessions.create_session(req.username.trim(), ttl);
    let max_age = ttl.saturating_mul(3600);
    let secure_attr = if state.listener_scheme == "https" {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax{secure_attr}; Max-Age={max_age}"
    );
    let mut resp = Json(json!({
        "ok": true,
        "data": {
            "token": token,
            "username": req.username.trim(),
            "default_credentials": state.db.is_default_credentials(),
            "https_enabled": state.listener_scheme == "https"
        }
    }))
    .into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    Ok(resp)
}

async fn api_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(tok) = extract_token_from_headers(&headers) {
        state.sessions.revoke(&tok);
    }
    let clear = format!("{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear.parse().unwrap());
    resp
}

async fn api_me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult {
    if let Some(tok) = extract_token_from_headers(&headers) {
        if let Some(username) = state.sessions.validate(&tok) {
            return ok_json(json!({
                "authenticated": true,
                "username": username,
                "default_credentials": state.db.is_default_credentials(),
                "https_enabled": state.listener_scheme == "https"
            }));
        }
    }
    ok_json(json!({ "authenticated": false }))
}

// ==================== Status & Shoes Process ====================

async fn api_core_history(State(state): State<Arc<AppState>>) -> ApiResult {
    ok_json(state.db.core_history().map_err(internal_err)?)
}

async fn api_daily_traffic(State(state): State<Arc<AppState>>) -> ApiResult {
    ok_json(state.db.daily_traffic().map_err(internal_err)?)
}

async fn api_status(State(state): State<Arc<AppState>>) -> ApiResult {
    let sys = state.monitor.snapshot();
    let shoes = state.proc_mgr.status().await;
    let totals = state.db.inbound_totals().map_err(internal_err)?;

    ok_json(json!({
        "system": sys,
        "shoes": shoes,
        "totals": totals
    }))
}

async fn api_shoes_start(State(state): State<Arc<AppState>>) -> ApiResult {
    let st = state.proc_mgr.start().await.map_err(bad_req)?;
    ok_json(st)
}

async fn api_shoes_stop(State(state): State<Arc<AppState>>) -> ApiResult {
    let st = state.proc_mgr.stop().await.map_err(bad_req)?;
    ok_json(st)
}

async fn api_shoes_restart(State(state): State<Arc<AppState>>) -> ApiResult {
    let st = state.proc_mgr.restart().await.map_err(bad_req)?;
    ok_json(st)
}

async fn api_shoes_reload(State(state): State<Arc<AppState>>) -> ApiResult {
    let yaml = state.proc_mgr.reload_config().await.map_err(bad_req)?;
    ok_json(json!({ "yaml": yaml }))
}

#[derive(Deserialize)]
struct LogsQuery {
    #[serde(default)]
    since: u64,
    #[serde(default = "default_log_limit")]
    limit: usize,
}
fn default_log_limit() -> usize {
    300
}

async fn api_shoes_logs(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LogsQuery>,
) -> ApiResult {
    ok_json(state.proc_mgr.get_logs(q.since, q.limit))
}

async fn api_shoes_logs_clear(State(state): State<Arc<AppState>>) -> ApiResult {
    state.proc_mgr.clear_logs();
    ok_json(true)
}

async fn api_shoes_config_preview(State(state): State<Arc<AppState>>) -> ApiResult {
    let settings = state.db.get_settings().map_err(internal_err)?;
    let certs = state.db.list_certificates().map_err(internal_err)?;
    let groups = state.db.list_outbound_groups().map_err(internal_err)?;
    let rules = state.db.list_routing_rules().map_err(internal_err)?;
    let inbounds = state.db.list_inbounds().map_err(internal_err)?;
    let yaml = build_shoes_yaml(
        &state.db.data_dir,
        &settings,
        &certs,
        &groups,
        &rules,
        &inbounds,
    )
    .map_err(bad_req)?;
    ok_json(json!({ "yaml": yaml, "path": settings.shoes_config_path }))
}

// ==================== Clash API Proxy ====================

async fn api_clash_connections(State(state): State<Arc<AppState>>) -> ApiResult {
    match state.monitor.fetch_connections_raw().await {
        Ok(v) => ok_json(v),
        Err(e) => ok_json(json!({
            "offline": true,
            "message": e.to_string(),
            "connections": [],
            "uploadTotal": 0,
            "downloadTotal": 0
        })),
    }
}

async fn api_clash_close_all_connections(State(state): State<Arc<AppState>>) -> ApiResult {
    state.monitor.close_connection(None).await.map_err(bad_req)?;
    ok_json(true)
}

async fn api_clash_close_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult {
    state
        .monitor
        .close_connection(Some(&id))
        .await
        .map_err(bad_req)?;
    ok_json(true)
}

async fn api_clash_proxies(State(state): State<Arc<AppState>>) -> ApiResult {
    match state.monitor.fetch_proxies().await {
        Ok(v) => ok_json(v),
        Err(e) => ok_json(json!({ "offline": true, "message": e.to_string(), "proxies": {} })),
    }
}

#[derive(Deserialize)]
struct SelectProxyReq {
    name: String,
}

async fn api_clash_select_proxy(
    State(state): State<Arc<AppState>>,
    Path(group): Path<String>,
    Json(req): Json<SelectProxyReq>,
) -> ApiResult {
    state
        .monitor
        .select_proxy(&group, &req.name)
        .await
        .map_err(bad_req)?;
    ok_json(true)
}

#[derive(Deserialize)]
struct DelayQuery {
    #[serde(default)]
    kind: String,
    name: String,
    url: Option<String>,
    timeout: Option<u64>,
}

async fn api_clash_delay(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DelayQuery>,
) -> ApiResult {
    let is_group = q.kind == "group";
    let res = state
        .monitor
        .test_delay(is_group, &q.name, q.url.as_deref(), q.timeout)
        .await
        .map_err(bad_req)?;
    ok_json(res)
}

// ==================== Inbounds & Clients ====================

async fn api_list_inbounds(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult {
    let inbounds = state.db.list_inbounds().map_err(internal_err)?;
    let settings = state.db.get_settings().map_err(internal_err)?;
    let host = resolve_share_host(&state, &settings, &headers, None);
    let active_map = state.monitor.snapshot().inbound_active_conns;

    let enriched: Vec<Value> = inbounds
        .into_iter()
        .map(|ib| {
            let active = active_map.get(&ib.tag).copied().unwrap_or(0);
            let shares: Vec<_> = ib
                .clients
                .iter()
                .map(|c| build_client_share_info(&ib, c, &host))
                .collect();
            let mut val = serde_json::to_value(&ib).unwrap_or_else(|_| json!({}));
            val["active_connections"] = json!(active);
            val["shares"] = json!(shares);
            val["share_host"] = json!(host);
            val["multi_user_supported"] = json!(ib.supports_multi_user());
            val
        })
        .collect();
    ok_json(enriched)
}

async fn api_create_inbound(
    State(state): State<Arc<AppState>>,
    Json(ib): Json<Inbound>,
) -> ApiResult {
    let created = state.db.create_inbound(ib).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config().await {
        // Roll back invalid inbound so DB and live config stay consistent
        let _ = state.db.delete_inbound(created.id);
        return Err(bad_req(format!("{e:#}")));
    }
    ok_json(created)
}

async fn api_update_inbound(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(ib): Json<Inbound>,
) -> ApiResult {
    let prev = state
        .db
        .get_inbound(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Inbound not found"))?;
    let updated = state.db.update_inbound(id, ib).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config().await {
        // Restore previous valid inbound configuration
        let _ = state.db.update_inbound(id, prev);
        return Err(bad_req(format!("{e:#}")));
    }
    ok_json(updated)
}

#[derive(Deserialize)]
struct ToggleReq {
    enable: bool,
}

async fn api_toggle_inbound(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(req): Json<ToggleReq>,
) -> ApiResult {
    let prev = state
        .db
        .get_inbound(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Inbound not found"))?;
    state
        .db
        .set_inbound_enable(id, req.enable)
        .map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config().await {
        let _ = state.db.set_inbound_enable(id, prev.enable);
        return Err(bad_req(e));
    }
    ok_json(true)
}

#[derive(Deserialize, Default)]
struct CloneInboundReq {
    remark: Option<String>,
    client_name: Option<String>,
    sub_id: Option<String>,
    port: Option<u16>,
}

/// Dedicated-port quick cloner: duplicates protocol/TLS/Reality settings onto a new port
/// with fresh client credentials so adding a new client takes 1 click!
async fn api_clone_inbound(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(req): Json<CloneInboundReq>,
) -> ApiResult {
    let mut src = state
        .db
        .get_inbound(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Source inbound not found"))?;

    let new_port = match req.port {
        Some(p) if p > 0 => p,
        _ => state
            .db
            .next_available_port(src.port.saturating_add(1))
            .map_err(internal_err)?,
    };

    src.id = 0;
    src.tag = String::new();
    src.port = new_port;
    src.up_bytes = 0;
    src.down_bytes = 0;
    src.enable = true;
    src.remark = req
        .remark
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("{}-{}", src.remark, new_port));

    let mut fresh_client = default_client_for_inbound(&src, 1);
    if let Some(cname) = req.client_name.filter(|s| !s.trim().is_empty()) {
        fresh_client.name = cname;
    }
    if let Some(sid) = req.sub_id.filter(|s| !s.trim().is_empty()) {
        fresh_client.sub_id = sid;
    }
    if src.stream_settings.security == "reality" && !src.stream_settings.reality.short_ids.is_empty()
    {
        src.stream_settings.reality.short_ids = vec![generate_short_id(16)];
    }
    src.clients = vec![fresh_client];

    let created = state.db.create_inbound(src).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config().await {
        let _ = state.db.delete_inbound(created.id);
        return Err(bad_req(e));
    }
    ok_json(created)
}

async fn api_reset_inbound_traffic(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    state.db.reset_inbound_traffic(id).map_err(bad_req)?;
    ok_json(true)
}

async fn api_reset_all_inbound_traffic(State(state): State<Arc<AppState>>) -> ApiResult {
    state.db.reset_all_traffic().map_err(bad_req)?;
    ok_json(true)
}

async fn api_delete_inbound(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    state.db.delete_inbound(id).map_err(bad_req)?;
    let _ = state.proc_mgr.reload_config().await;
    ok_json(true)
}

#[derive(Deserialize, Default)]
struct ShareQuery {
    host: Option<String>,
}

async fn api_inbound_share(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Query(q): Query<ShareQuery>,
) -> ApiResult {
    let ib = state
        .db
        .get_inbound(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Inbound not found"))?;
    let settings = state.db.get_settings().map_err(internal_err)?;
    let host = resolve_share_host(&state, &settings, &headers, q.host.as_deref());
    let list: Vec<_> = ib
        .clients
        .iter()
        .map(|c| build_client_share_info(&ib, c, &host))
        .collect();
    ok_json(list)
}

async fn api_add_client(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(client): Json<ClientRecord>,
) -> ApiResult {
    let updated = state.db.add_client(id, client).map_err(bad_req)?;
    state.proc_mgr.reload_config().await.map_err(bad_req)?;
    ok_json(updated)
}

async fn api_update_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<i64>,
    Json(client): Json<ClientRecord>,
) -> ApiResult {
    let updated = state.db.update_client(client_id, client).map_err(bad_req)?;
    state.proc_mgr.reload_config().await.map_err(bad_req)?;
    ok_json(updated)
}

async fn api_delete_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<i64>,
) -> ApiResult {
    let updated = state.db.delete_client(client_id).map_err(bad_req)?;
    state.proc_mgr.reload_config().await.map_err(bad_req)?;
    ok_json(updated)
}

#[derive(Deserialize)]
struct NextPortQuery {
    #[serde(default = "default_start_port")]
    start: u16,
}
fn default_start_port() -> u16 {
    20000
}

async fn api_next_port(
    State(state): State<Arc<AppState>>,
    Query(q): Query<NextPortQuery>,
) -> ApiResult {
    let port = state.db.next_available_port(q.start).map_err(internal_err)?;
    ok_json(json!({ "port": port }))
}

// ==================== Keygen ====================

async fn api_keygen_uuid() -> ApiResult {
    ok_json(json!({ "uuid": generate_uuid() }))
}

async fn api_keygen_reality() -> ApiResult {
    let (priv_k, pub_k) = generate_reality_keypair();
    ok_json(json!({
        "private_key": priv_k,
        "public_key": pub_k,
        "short_id": generate_short_id(16)
    }))
}

#[derive(Deserialize)]
struct Ss2022Query {
    #[serde(default = "default_ss2022_cipher")]
    cipher: String,
}
fn default_ss2022_cipher() -> String {
    "2022-blake3-aes-256-gcm".to_string()
}

async fn api_keygen_ss2022(Query(q): Query<Ss2022Query>) -> ApiResult {
    let pwd = generate_ss2022_password(&q.cipher).map_err(bad_req)?;
    ok_json(json!({ "cipher": q.cipher, "password": pwd }))
}

#[derive(Deserialize)]
struct RandomQuery {
    #[serde(default = "default_rand_len")]
    len: usize,
}
fn default_rand_len() -> usize {
    20
}

async fn api_keygen_random(Query(q): Query<RandomQuery>) -> ApiResult {
    ok_json(json!({ "secret": generate_random_alnum(q.len.clamp(6, 64)) }))
}

// ==================== Certificates ====================

#[derive(serde::Serialize)]
struct CertificateListItem {
    #[serde(flatten)]
    cert: CertificateRecord,
    runtime: CertRuntimeStatus,
}

fn inbounds_referencing_cert(inbounds: &[Inbound], cert_name: &str) -> Vec<String> {
    let target = cert_name.trim();
    inbounds
        .iter()
        .filter(|ib| {
            let tls = &ib.stream_settings.tls;
            (ib.is_quic() || ib.stream_settings.security == "tls")
                && tls.certificate_source.trim() == target
                && (tls.cert_mode == "source"
                    || (tls.cert_file.trim().is_empty() && tls.key_file.trim().is_empty()))
        })
        .map(|ib| {
            if ib.remark.trim().is_empty() {
                format!("{} (:{})", ib.tag, ib.port)
            } else {
                format!("{} (:{})", ib.remark.trim(), ib.port)
            }
        })
        .collect()
}

async fn api_list_certs(State(state): State<Arc<AppState>>) -> ApiResult {
    let certs = state.db.list_certificates().map_err(internal_err)?;
    let inbounds = state.db.list_inbounds().unwrap_or_default();
    let settings = state.db.get_settings().ok();
    let panel_cert = settings
        .as_ref()
        .map(|s| s.panel_cert_file.as_str())
        .unwrap_or("");

    let enriched: Vec<CertificateListItem> = certs
        .into_iter()
        .map(|cert| {
            let used_by = inbounds_referencing_cert(&inbounds, &cert.name);
            let runtime = inspect_certificate_runtime(
                &state.db.data_dir,
                &cert,
                used_by,
                panel_cert,
            );
            CertificateListItem { cert, runtime }
        })
        .collect();
    ok_json(enriched)
}

#[derive(Deserialize)]
struct AcmeMetaQuery {
    #[serde(default)]
    directory_url: String,
}

async fn api_acme_meta(Query(q): Query<AcmeMetaQuery>) -> ApiResult {
    let dir_url = if q.directory_url.trim().is_empty() {
        DEFAULT_LETSENCRYPT_DIR
    } else {
        q.directory_url.trim()
    };
    let meta = fetch_acme_directory_meta(dir_url).await.map_err(bad_req)?;
    ok_json(meta)
}

async fn save_cert_with_rollback(
    state: &AppState,
    cert: CertificateRecord,
) -> Result<CertificateRecord, (StatusCode, Json<Value>)> {
    let previous = if cert.id > 0 {
        state.db.get_certificate(cert.id).ok().flatten()
    } else {
        None
    };
    let saved = state.db.save_certificate(cert).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config().await {
        if let Some(prev) = previous {
            let _ = state.db.restore_certificate(&prev);
        } else {
            let _ = state.db.delete_certificate(saved.id);
        }
        return Err(bad_req(e));
    }
    Ok(saved)
}

async fn api_save_cert(
    State(state): State<Arc<AppState>>,
    Json(mut cert): Json<CertificateRecord>,
) -> ApiResult {
    cert.name = cert.name.trim().to_string();
    cert.cert_type = cert.cert_type.trim().to_string();

    if cert.cert_type == "acme" {
        cert.domains = normalize_acme_domains(&cert.domains).map_err(bad_req)?;
        if cert.directory_url.trim().is_empty() {
            cert.directory_url = DEFAULT_LETSENCRYPT_DIR.to_string();
        } else {
            cert.directory_url = cert.directory_url.trim().to_string();
        }
        if cert.challenge_type != "tls_alpn01" {
            cert.challenge_type = "http01".to_string();
            if cert.http01_listen.trim().is_empty() {
                cert.http01_listen = "0.0.0.0:80".to_string();
            }
        }
        // Always fetch the live ACME directory Terms of Service URL so Shoes never fails on stale LE-SA URLs.
        match fetch_acme_directory_meta(&cert.directory_url).await {
            Ok(meta) => {
                cert.terms_of_service = meta.terms_of_service.unwrap_or_default();
            }
            Err(e) => {
                // If user passed an unreachable custom URL or transient error, keep fallback for LE or surface error clearly.
                if cert.directory_url.contains("letsencrypt.org") {
                    if cert.terms_of_service.trim().is_empty()
                        || cert.terms_of_service.contains("LE-SA-v1.4-April-3-2024")
                    {
                        cert.terms_of_service = DEFAULT_LETSENCRYPT_TOS.to_string();
                    }
                } else if cert.terms_of_service.trim().is_empty() {
                    return Err(bad_req(format!(
                        "Failed to fetch ACME directory metadata from {}: {e}",
                        cert.directory_url
                    )));
                }
            }
        }
    } else if cert.cert_type == "files" {
        let cert_path = cert.cert_file.trim();
        let key_path = cert.key_file.trim();
        if cert_path.is_empty() || key_path.is_empty() {
            return Err(bad_req("Both certificate file path and key file path are required"));
        }
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| bad_req(format!("Cannot read certificate file '{cert_path}': {e}")))?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| bad_req(format!("Cannot read private key file '{key_path}': {e}")))?;
        let info = validate_cert_key_pair(&cert_pem, &key_pem)
            .await
            .map_err(bad_req)?;
        if cert.domains.is_empty() && !info.sans.is_empty() {
            cert.domains = info.sans;
        }
    }

    let saved = save_cert_with_rollback(&state, cert).await?;
    ok_json(saved)
}

#[derive(Deserialize)]
struct UploadCertReq {
    #[serde(default)]
    id: i64,
    name: String,
    cert_pem: String,
    key_pem: String,
    #[serde(default)]
    remark: String,
}

async fn api_upload_cert(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UploadCertReq>,
) -> ApiResult {
    let safe_name = sanitize_cert_filename(&req.name);
    if req.name.trim().is_empty() {
        return Err(bad_req("Certificate name must not be empty"));
    }
    let info = validate_cert_key_pair(&req.cert_pem, &req.key_pem)
        .await
        .map_err(bad_req)?;

    let cert_dir = state.db.data_dir.join("certs");
    let cert_path = cert_dir.join(format!("{safe_name}.crt"));
    let key_path = cert_dir.join(format!("{safe_name}.key"));
    write_cert_and_key_atomic(&cert_path, &key_path, &req.cert_pem, &req.key_pem)
        .map_err(internal_err)?;

    let rec = CertificateRecord {
        id: req.id,
        name: safe_name,
        cert_type: "files".to_string(),
        cert_file: cert_path.to_string_lossy().replace('\\', "/"),
        key_file: key_path.to_string_lossy().replace('\\', "/"),
        domains: info.sans,
        email: String::new(),
        directory_url: String::new(),
        terms_of_service: String::new(),
        challenge_type: "http01".to_string(),
        http01_listen: String::new(),
        remark: req.remark,
        created_at: 0,
    };
    let saved = save_cert_with_rollback(&state, rec).await?;
    let _ = reload_panel_https_if_matching(&state, &cert_path, &key_path).await;
    ok_json(saved)
}

#[derive(Deserialize)]
struct SelfSignedReq {
    name: String,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    remark: String,
}

async fn api_self_signed_cert(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SelfSignedReq>,
) -> ApiResult {
    if req.name.trim().is_empty() {
        return Err(bad_req("Certificate name must not be empty"));
    }
    let safe_name = sanitize_cert_filename(&req.name);

    let mut domains: Vec<String> = req
        .domains
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if domains.is_empty() {
        if let Ok(settings) = state.db.get_settings() {
            let ph = settings.public_host.trim().to_string();
            if !ph.is_empty() && !is_loopback_or_unspecified_host(&ph) {
                domains.push(ph);
            }
        }
        let detected = state.get_detected_public_ip();
        if !detected.is_empty() && !domains.contains(&detected) {
            domains.push(detected);
        }
        domains.push("localhost".to_string());
        domains.push("127.0.0.1".to_string());
    }

    let (cert_pem, key_pem) = generate_self_signed_cert(&domains).map_err(bad_req)?;
    let cert_dir = state.db.data_dir.join("certs");
    let cert_path = cert_dir.join(format!("{safe_name}.crt"));
    let key_path = cert_dir.join(format!("{safe_name}.key"));
    write_cert_and_key_atomic(&cert_path, &key_path, &cert_pem, &key_pem).map_err(internal_err)?;

    let rec = CertificateRecord {
        id: 0,
        name: safe_name,
        cert_type: "files".to_string(),
        cert_file: cert_path.to_string_lossy().replace('\\', "/"),
        key_file: key_path.to_string_lossy().replace('\\', "/"),
        domains,
        email: String::new(),
        directory_url: String::new(),
        terms_of_service: String::new(),
        challenge_type: "http01".to_string(),
        http01_listen: String::new(),
        remark: if req.remark.trim().is_empty() {
            "Self-Signed".to_string()
        } else {
            req.remark.trim().to_string()
        },
        created_at: 0,
    };
    let saved = save_cert_with_rollback(&state, rec).await?;
    ok_json(saved)
}

#[derive(Deserialize)]
struct IssueIpCertReq {
    #[serde(default)]
    id: i64,
    name: String,
    ips: Vec<String>,
    #[serde(default)]
    email: String,
    #[serde(default)]
    directory_url: String,
    #[serde(default)]
    http01_listen: String,
    #[serde(default)]
    remark: String,
}

async fn api_issue_ip_cert(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IssueIpCertReq>,
) -> ApiResult {
    if req.name.trim().is_empty() {
        return Err(bad_req("Certificate name must not be empty"));
    }
    let safe_name = sanitize_cert_filename(&req.name);
    let dir_url = if req.directory_url.trim().is_empty() {
        DEFAULT_LETSENCRYPT_DIR.to_string()
    } else {
        req.directory_url.trim().to_string()
    };
    let listen = if req.http01_listen.trim().is_empty() {
        "0.0.0.0:80".to_string()
    } else {
        req.http01_listen.trim().to_string()
    };

    let issued = issue_shortlived_ip_cert(
        &state.db.data_dir,
        &safe_name,
        &req.ips,
        &req.email,
        &dir_url,
        &listen,
    )
    .await
    .map_err(bad_req)?;

    let cert_dir = state.db.data_dir.join("certs");
    let cert_path = cert_dir.join(format!("{safe_name}.crt"));
    let key_path = cert_dir.join(format!("{safe_name}.key"));
    write_cert_and_key_atomic(&cert_path, &key_path, &issued.cert_pem, &issued.key_pem)
        .map_err(internal_err)?;

    let existing_id = if req.id > 0 {
        req.id
    } else {
        state
            .db
            .list_certificates()
            .ok()
            .and_then(|list| list.into_iter().find(|c| c.name == safe_name).map(|c| c.id))
            .unwrap_or(0)
    };

    let norm_ips: Vec<String> = req
        .ips
        .into_iter()
        .map(|s| s.trim().trim_matches(['[', ']']).to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let rec = CertificateRecord {
        id: existing_id,
        name: safe_name,
        cert_type: "acme_ip".to_string(),
        cert_file: cert_path.to_string_lossy().replace('\\', "/"),
        key_file: key_path.to_string_lossy().replace('\\', "/"),
        domains: if issued.info.sans.is_empty() {
            norm_ips
        } else {
            issued.info.sans.clone()
        },
        email: req.email.trim().to_string(),
        directory_url: dir_url,
        terms_of_service: issued.terms_of_service,
        challenge_type: "http01".to_string(),
        http01_listen: listen,
        remark: if req.remark.trim().is_empty() {
            "Let's Encrypt IP SSL (shortlived 6d auto-renew)".to_string()
        } else {
            req.remark.trim().to_string()
        },
        created_at: 0,
    };
    let saved = save_cert_with_rollback(&state, rec).await?;
    let _ = reload_panel_https_if_matching(&state, &cert_path, &key_path).await;
    ok_json(json!({
        "cert": saved,
        "info": issued.info,
    }))
}

async fn api_renew_cert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let cert = state
        .db
        .get_certificate(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Certificate not found"))?;
    match cert.cert_type.as_str() {
        "acme_ip" => {
            let info = renew_ip_certificate_record(&state, &cert)
                .await
                .map_err(bad_req)?;
            ok_json(json!({
                "renewed": true,
                "info": info,
            }))
        }
        "acme" => {
            state.proc_mgr.reload_config().await.map_err(bad_req)?;
            ok_json(json!({
                "renewed": false,
                "message": "Triggered Shoes config reload; Shoes manages domain ACME issuance & renewal automatically in the background.",
            }))
        }
        _ => Err(bad_req("Only ACME certificates support automatic renewal")),
    }
}

async fn api_apply_panel_https(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let cert = state
        .db
        .get_certificate(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Certificate not found"))?;

    let (cert_path, key_path) = if cert.cert_type == "acme" {
        export_acme_state_for_panel(&state.db.data_dir, &cert).map_err(bad_req)?
    } else {
        let cp = std::path::PathBuf::from(cert.cert_file.trim());
        let kp = std::path::PathBuf::from(cert.key_file.trim());
        if !cp.is_file() || !kp.is_file() {
            return Err(bad_req("Certificate or private key file does not exist on disk"));
        }
        (cp, kp)
    };

    // Verify PEM pair before persisting to Panel HTTPS settings
    axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .map_err(|e| bad_req(format!("Invalid TLS certificate/key for Panel HTTPS: {e}")))?;

    let cert_str = cert_path.to_string_lossy().replace('\\', "/");
    let key_str = key_path.to_string_lossy().replace('\\', "/");
    state
        .db
        .set_setting_kv("panel_cert_file", &cert_str)
        .map_err(internal_err)?;
    state
        .db
        .set_setting_kv("panel_key_file", &key_str)
        .map_err(internal_err)?;

    let hot_reloaded = reload_panel_https_if_matching(&state, &cert_path, &key_path)
        .await
        .unwrap_or(false);

    ok_json(json!({
        "panel_cert_file": cert_str,
        "panel_key_file": key_str,
        "hot_reloaded": hot_reloaded,
        "restart_required": !hot_reloaded,
    }))
}

async fn api_delete_cert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let existing = state
        .db
        .get_certificate(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Certificate not found"))?;

    let inbounds = state.db.list_inbounds().unwrap_or_default();
    let used_by = inbounds_referencing_cert(&inbounds, &existing.name);
    if !used_by.is_empty() {
        return Err(bad_req(format!(
            "Certificate '{}' is still used by inbound(s): {}. Switch or disable those inbounds first.",
            existing.name,
            used_by.join(", ")
        )));
    }

    if let Ok(settings) = state.db.get_settings() {
        let panel_cert = settings.panel_cert_file.trim().replace('\\', "/");
        let cert_norm = existing.cert_file.trim().replace('\\', "/");
        if !panel_cert.is_empty() && !cert_norm.is_empty() && panel_cert == cert_norm {
            return Err(bad_req(format!(
                "Certificate '{}' is currently configured as the Panel HTTPS certificate. Clear Panel HTTPS in Settings first.",
                existing.name
            )));
        }
    }

    state.db.delete_certificate(id).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config().await {
        let _ = state.db.restore_certificate(&existing);
        return Err(bad_req(e));
    }
    ok_json(true)
}

// ==================== Outbound Groups & Routing ====================

async fn api_list_outbound_groups(State(state): State<Arc<AppState>>) -> ApiResult {
    ok_json(state.db.list_outbound_groups().map_err(internal_err)?)
}

async fn api_save_outbound_group(
    State(state): State<Arc<AppState>>,
    Json(g): Json<OutboundGroupRecord>,
) -> ApiResult {
    let saved = state.db.save_outbound_group(g).map_err(bad_req)?;
    state.proc_mgr.reload_config().await.map_err(bad_req)?;
    ok_json(saved)
}

async fn api_delete_outbound_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    state.db.delete_outbound_group(id).map_err(bad_req)?;
    state.proc_mgr.reload_config().await.map_err(bad_req)?;
    ok_json(true)
}

async fn api_list_routing_rules(State(state): State<Arc<AppState>>) -> ApiResult {
    ok_json(state.db.list_routing_rules().map_err(internal_err)?)
}

async fn api_save_routing_rule(
    State(state): State<Arc<AppState>>,
    Json(r): Json<RoutingRuleRecord>,
) -> ApiResult {
    let saved = state.db.save_routing_rule(r).map_err(bad_req)?;
    state.proc_mgr.reload_config().await.map_err(bad_req)?;
    ok_json(saved)
}

async fn api_delete_routing_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    state.db.delete_routing_rule(id).map_err(bad_req)?;
    state.proc_mgr.reload_config().await.map_err(bad_req)?;
    ok_json(true)
}

// ==================== Subscriptions ====================

async fn api_list_subscriptions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult {
    let subs = state.db.subscriptions_with_counts().map_err(internal_err)?;
    let settings = state.db.get_settings().map_err(internal_err)?;

    let base_url = if !settings.sub_public_url.trim().is_empty() {
        settings.sub_public_url.trim().trim_end_matches('/').to_string()
    } else if let Some(xfh) = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim())
        .filter(|s| !s.is_empty() && !is_loopback_or_unspecified_host(&strip_host_port(s)))
    {
        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or("http").trim())
            .unwrap_or("http");
        format!("{proto}://{xfh}")
    } else {
        let host = resolve_share_host(&state, &settings, &headers, None);
        let scheme = state.listener_scheme;
        let host_fmt = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host
        };
        format!("{scheme}://{host_fmt}:{}", state.listener_port)
    };

    let enriched: Vec<Value> = subs
        .into_iter()
        .map(|(s, node_count)| {
            let sub_url = format!("{base_url}/sub/{}", s.token);
            let mut v = serde_json::to_value(&s).unwrap_or_else(|_| json!({}));
            v["node_count"] = json!(node_count);
            v["url_auto"] = json!(sub_url);
            v["url_v2ray"] = json!(format!("{sub_url}?format=v2ray"));
            v["url_clash"] = json!(format!("{sub_url}?format=clash"));
            v["url_singbox"] = json!(format!("{sub_url}?format=singbox"));
            v
        })
        .collect();
    ok_json(enriched)
}

async fn api_save_subscription(
    State(state): State<Arc<AppState>>,
    Json(sub): Json<SubscriptionRecord>,
) -> ApiResult {
    let saved = state.db.save_subscription(sub).map_err(bad_req)?;
    ok_json(saved)
}

async fn api_rotate_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let saved = state.db.rotate_subscription_token(id).map_err(bad_req)?;
    ok_json(saved)
}

async fn api_delete_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    state.db.delete_subscription(id).map_err(bad_req)?;
    ok_json(true)
}

async fn public_subscription_handler(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sub = match state.db.find_subscription_by_token(token.trim()) {
        Ok(Some(s)) => s,
        _ => {
            return (StatusCode::NOT_FOUND, "Subscription not found or disabled").into_response();
        }
    };
    let Ok(inbounds) = state.db.list_inbounds() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
    };
    let certs = state.db.list_certificates().unwrap_or_default();
    let Ok(settings) = state.db.get_settings() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Settings error").into_response();
    };

    let host = resolve_share_host(
        &state,
        &settings,
        &headers,
        query.get("host").map(String::as_str),
    );
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok());
    let fmt = SubFormat::detect(query.get("format").map(String::as_str), ua);

    let payload = generate_subscription_with_certs(&inbounds, &certs, &sub.sub_id, &host, fmt);

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, payload.content_type)
        .header("subscription-userinfo", payload.userinfo_header)
        .header("profile-update-interval", "12")
        .body(Body::from(payload.body))
        .unwrap();

    if let Ok(hv) = sub.name.parse() {
        resp.headers_mut().insert("profile-title", hv);
    }
    resp
}

// ==================== Settings & Account ====================

async fn api_get_settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult {
    let s = state.db.get_settings().map_err(internal_err)?;
    let username = state.db.get_admin_username().unwrap_or_else(|_| "admin".to_string());
    let effective_host = resolve_share_host(&state, &s, &headers, None);
    ok_json(json!({
        "settings": s,
        "admin_username": username,
        "effective_share_host": effective_host,
        "detected_public_ip": state.get_detected_public_ip(),
        "listener_scheme": state.listener_scheme,
        "default_credentials": state.db.is_default_credentials()
    }))
}

#[derive(Deserialize)]
struct SetPublicHostReq {
    public_host: String,
}

async fn api_set_public_host(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetPublicHostReq>,
) -> ApiResult {
    let h = strip_host_port(req.public_host.trim());
    state
        .db
        .set_setting_kv("public_host", &h)
        .map_err(bad_req)?;
    ok_json(json!({ "public_host": h }))
}

async fn api_save_settings(
    State(state): State<Arc<AppState>>,
    Json(s): Json<PanelSettings>,
) -> ApiResult {
    // Finish applying or rolling back even if the browser disconnects.
    let saved = tokio::spawn(async move {
        let _operation = state.proc_mgr.operation.lock().await;
        state.proc_mgr.apply_settings(&s).await?;
        state.set_base_path(&s.panel_base_path);
        state.db.get_settings()
    })
    .await
    .map_err(internal_err)?
    .map_err(|e| bad_req(format!("{e:#}")))?;
    ok_json(saved)
}

#[derive(Deserialize)]
struct ChangePwdReq {
    current_password: String,
    new_username: String,
    #[serde(default)]
    new_password: String,
}

async fn api_change_password(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChangePwdReq>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    state
        .db
        .update_credentials(
            Some(&req.current_password),
            &req.new_username,
            &req.new_password,
        )
        .map_err(bad_req)?;
    state.sessions.revoke_all();
    let clear = format!("{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    let mut resp = Json(json!({ "ok": true, "data": true })).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear.parse().unwrap());
    Ok(resp)
}

async fn api_backup_db(
    State(state): State<Arc<AppState>>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let db = state.db.clone();
    let bytes = tokio::task::spawn_blocking(move || db.backup_snapshot())
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"shoes-panel-backup.db\"",
        )
        .body(Body::from(bytes))
        .unwrap())
}

async fn apply_post_restore(state: &AppState, pre_backup: String) -> ApiResult {
    if let Ok(settings) = state.db.get_settings() {
        state.set_base_path(&settings.panel_base_path);
    }
    // Reload shoes config with restored inbounds/certs/routing (log warning if shoes bin missing)
    let reload_note = match state.proc_mgr.reload_config().await {
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    };
    state.sessions.revoke_all();
    ok_json(json!({
        "restored": true,
        "pre_restore_backup": pre_backup,
        "reload_warning": reload_note,
    }))
}

async fn api_restore_db(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> ApiResult {
    let mut uploaded: Option<Vec<u8>> = None;
    while let Some(field) = multipart.next_field().await.map_err(bad_req)? {
        let is_file_field = field.name() == Some("file") || field.file_name().is_some();
        if is_file_field {
            let data = field.bytes().await.map_err(bad_req)?;
            if !data.is_empty() {
                uploaded = Some(data.to_vec());
                break;
            }
        }
    }
    let bytes = uploaded.ok_or_else(|| bad_req("No SQLite .db file uploaded"))?;
    let db = state.db.clone();
    let pre_backup = tokio::task::spawn_blocking(move || db.restore_from_bytes(&bytes))
        .await
        .map_err(internal_err)?
        .map_err(bad_req)?;
    apply_post_restore(&state, pre_backup).await
}

async fn api_list_backups(State(state): State<Arc<AppState>>) -> ApiResult {
    let list = list_local_backups(&state.db.data_dir).map_err(internal_err)?;
    ok_json(list)
}

#[derive(Deserialize, Default)]
struct BackupNowReq {
    #[serde(default)]
    send_telegram: bool,
}

async fn api_backup_now(
    State(state): State<Arc<AppState>>,
    body: Option<Json<BackupNowReq>>,
) -> ApiResult {
    let req = body.map(|b| b.0).unwrap_or_default();
    let settings = state.db.get_settings().map_err(internal_err)?;
    let retain = settings.auto_backup_retain_count.clamp(1, 100) as usize;
    let db = state.db.clone();
    let (entry, bytes) =
        tokio::task::spawn_blocking(move || create_local_backup(&db, "manual", Some(retain)))
            .await
            .map_err(internal_err)?
            .map_err(internal_err)?;

    let mut tg_sent = 0usize;
    if req.send_telegram
        || (settings.tg_backup_enabled
            && !settings.tg_bot_token.trim().is_empty()
            && !settings.tg_chat_id.trim().is_empty())
    {
        let host = if !settings.public_host.trim().is_empty() {
            settings.public_host.clone()
        } else {
            state.get_detected_public_ip()
        };
        let caption = build_backup_caption(&state.db, &host);
        tg_sent = send_backup_to_telegram(
            None,
            &settings.tg_bot_token,
            &settings.tg_chat_id,
            &entry.filename,
            &bytes,
            &caption,
        )
        .await
        .map_err(bad_req)?;
    }

    ok_json(json!({
        "backup": entry,
        "telegram_sent": tg_sent,
    }))
}

#[derive(Deserialize, Default)]
struct TgBackupTestReq {
    #[serde(default)]
    tg_bot_token: String,
    #[serde(default)]
    tg_chat_id: String,
}

async fn api_backup_tg_test(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TgBackupTestReq>,
) -> ApiResult {
    let settings = state.db.get_settings().map_err(internal_err)?;
    let token = if !req.tg_bot_token.trim().is_empty() {
        req.tg_bot_token.trim().to_string()
    } else {
        settings.tg_bot_token.trim().to_string()
    };
    let chat_id = if !req.tg_chat_id.trim().is_empty() {
        req.tg_chat_id.trim().to_string()
    } else {
        settings.tg_chat_id.trim().to_string()
    };
    let db = state.db.clone();
    let bytes = tokio::task::spawn_blocking(move || db.backup_snapshot())
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;
    let filename = format!(
        "shoes-panel-test-{}.db",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    let host = if !settings.public_host.trim().is_empty() {
        settings.public_host.clone()
    } else {
        state.get_detected_public_ip()
    };
    let caption = build_backup_caption(&state.db, &host);
    let sent = send_backup_to_telegram(None, &token, &chat_id, &filename, &bytes, &caption)
        .await
        .map_err(bad_req)?;
    ok_json(json!({ "sent_chats": sent, "filename": filename }))
}

async fn api_download_local_backup(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let safe = sanitize_backup_filename(&filename).map_err(bad_req)?;
    let path = backups_dir(&state.db.data_dir).join(&safe);
    let bytes = std::fs::read(&path)
        .map_err(|_| err_json(StatusCode::NOT_FOUND, format!("Backup '{safe}' not found")))?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{safe}\""),
        )
        .body(Body::from(bytes))
        .unwrap())
}

async fn api_restore_local_backup(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> ApiResult {
    let safe = sanitize_backup_filename(&filename).map_err(bad_req)?;
    let path = backups_dir(&state.db.data_dir).join(&safe);
    let bytes = std::fs::read(&path)
        .map_err(|_| err_json(StatusCode::NOT_FOUND, format!("Backup '{safe}' not found")))?;
    let db = state.db.clone();
    let pre_backup = tokio::task::spawn_blocking(move || db.restore_from_bytes(&bytes))
        .await
        .map_err(internal_err)?
        .map_err(bad_req)?;
    apply_post_restore(&state, pre_backup).await
}

async fn api_delete_local_backup(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> ApiResult {
    let safe = sanitize_backup_filename(&filename).map_err(bad_req)?;
    let path = backups_dir(&state.db.data_dir).join(&safe);
    if !path.is_file() {
        return Err(err_json(
            StatusCode::NOT_FOUND,
            format!("Backup '{safe}' not found"),
        ));
    }
    std::fs::remove_file(&path).map_err(internal_err)?;
    ok_json(true)
}

// ==================== Panel Restart & GitHub Online Updates ====================

async fn api_panel_restart(State(state): State<Arc<AppState>>) -> ApiResult {
    let settings = state.db.get_settings().map_err(internal_err)?;
    let target_scheme = settings.scheme();
    let target_port = settings.panel_port;
    let target_base_path = settings.panel_base_path.clone();
    schedule_panel_restart(state, 700);
    ok_json(json!({
        "restarting": true,
        "target_scheme": target_scheme,
        "target_port": target_port,
        "target_base_path": target_base_path,
    }))
}

#[derive(Deserialize, Default)]
struct UpdatesQuery {
    #[serde(default)]
    force: Option<String>,
}

async fn api_check_updates(
    State(state): State<Arc<AppState>>,
    Query(q): Query<UpdatesQuery>,
) -> ApiResult {
    let force = matches!(q.force.as_deref(), Some("1" | "true" | "yes"));
    let result = check_github_updates(&state.db, &state.proc_mgr, force).await;
    ok_json(result)
}

async fn api_upgrade_panel(State(state): State<Arc<AppState>>) -> ApiResult {
    let res = upgrade_panel_binary(state).await.map_err(bad_req)?;
    ok_json(res)
}

async fn api_upgrade_shoes(State(state): State<Arc<AppState>>) -> ApiResult {
    let res = upgrade_shoes_binary(state).await.map_err(bad_req)?;
    ok_json(res)
}

// ==================== Embedded SPA Fallback ====================

async fn serve_spa(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let raw_path = req.uri().path().trim_start_matches('/');
    let asset_path = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    if let Some(file) = WebAssets::get(asset_path) {
        let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
        if asset_path == "index.html" {
            return render_index_with_base(&state, file.data.as_ref());
        }
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(Body::from(file.data.into_owned()))
            .unwrap();
    }

    // SPA client-side routing fallback -> serve index.html
    if !raw_path.starts_with("api/") {
        if let Some(index) = WebAssets::get("index.html") {
            return render_index_with_base(&state, index.data.as_ref());
        }
    }

    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

fn render_index_with_base(state: &AppState, raw_html: &[u8]) -> Response {
    let bp = state.get_base_path();
    let html = String::from_utf8_lossy(raw_html);
    let injected = html.replace(
        "<head>",
        &format!(
            "<head><script>window.__SHOES_BASE__={};</script>",
            serde_json::to_string(&bp).unwrap_or_else(|_| "\"/\"".to_string())
        ),
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(injected))
        .unwrap()
}
