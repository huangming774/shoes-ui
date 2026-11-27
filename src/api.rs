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
use crate::auth::{extract_cluster_token_from_headers, extract_token_from_headers, SESSION_COOKIE_NAME};
use crate::cluster::{
    effective_node_prefix, ClusterExportPayload, ClusterShoesSummary, ClusterSystemSummary,
    RemoteNodeSnapshot,
};
use crate::crypto_util::{
    generate_random_alnum, generate_reality_keypair, generate_self_signed_cert,
    generate_short_id, generate_ss2022_password, generate_uuid, generate_wireguard_keypair,
};
use crate::db::{default_client_for_inbound, ConfigTable};
use crate::models::{
    CertificateRecord, ClientRecord, ClusterNodeRecord, DnsGroupRecord, Inbound,
    OutboundGroupRecord, PanelSettings, RoutingRuleRecord, RuleSourceGroupRecord,
    SubscriptionRecord, SubscriptionTemplateConfig, DEFAULT_LETSENCRYPT_DIR,
    DEFAULT_LETSENCRYPT_TOS,
};
use crate::ops_util::{
    backups_dir, build_backup_caption, check_github_updates, create_local_backup,
    list_local_backups, parse_wireguard_conf, register_cloudflare_warp, sanitize_backup_filename,
    schedule_panel_restart, send_backup_to_telegram, sync_rule_source_group, upgrade_panel_binary,
    upgrade_shoes_binary,
};
use crate::state::{is_loopback_or_unspecified_host, AppState};
use crate::sub_gen::{
    build_client_share_info, collect_public_cert_pems, generate_aggregated_subscription,
    SubFormat, SubSourceNode,
};
use crate::yaml_gen::{build_shoes_yaml_full, normalize_acme_domains};

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
    let service_api = Router::new()
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
        .route("/clash/delay", get(api_clash_delay));
    let inbound_api = Router::new()
        // Inbounds & Clients (Two-Layer Model)
        .route("/inbounds", get(api_list_inbounds).post(api_create_inbound))
        .route("/inbounds/batch", post(api_batch_inbounds))
        .route("/inbounds/import/preview", post(api_import_inbounds_preview))
        .route("/inbounds/import/apply", post(api_import_inbounds_apply))
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
        .route("/next-port", get(api_next_port));
    let tools_api = Router::new()
        // Keygen utilities
        .route("/keygen/uuid", get(api_keygen_uuid))
        .route("/keygen/reality", get(api_keygen_reality))
        .route("/keygen/ss2022", get(api_keygen_ss2022))
        .route("/keygen/random", get(api_keygen_random))
        .route("/keygen/wireguard", get(api_keygen_wireguard))
        .route("/keygen/warp", post(api_keygen_warp))
        .route("/keygen/parse-wg-conf", post(api_parse_wg_conf))
        .route("/keygen/vless-encryption", get(api_keygen_vless_encryption))
        .route("/keygen/mldsa65", get(api_keygen_mldsa65))
        .route("/keygen/mtls-client", get(api_keygen_mtls_client))
        .route("/tools/probe-reality", post(api_probe_reality))
        .route("/tools/probe-egress", post(api_probe_egress));
    let certs_api = Router::new()
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
        .route("/certificates/{id}", delete(api_delete_cert));
    let routing_api = Router::new()
        // Outbound Groups, DNS Groups, Rule Sources & Routing Rules
        .route(
            "/outbound-groups",
            get(api_list_outbound_groups).post(api_save_outbound_group),
        )
        .route("/outbound-groups/parse-uri", post(api_parse_outbound_uri))
        .route("/outbound-groups/{id}", delete(api_delete_outbound_group))
        .route(
            "/dns-groups",
            get(api_list_dns_groups).post(api_save_dns_group),
        )
        .route("/dns-groups/{id}", delete(api_delete_dns_group))
        .route(
            "/rule-sources",
            get(api_list_rule_sources).post(api_save_rule_source),
        )
        .route("/rule-sources/{id}/sync", post(api_sync_rule_source))
        .route("/rule-sources/{id}", delete(api_delete_rule_source))
        .route(
            "/routing-rules",
            get(api_list_routing_rules).post(api_save_routing_rule),
        )
        .route("/routing-rules/{id}", delete(api_delete_routing_rule));
    let config_api = inbound_api
        .merge(certs_api)
        .merge(routing_api)
        .route_layer(middleware::from_fn(
        |req: Request, next: Next| async move {
            if req.method().is_safe() {
                return Ok(next.run(req).await);
            }
            // Complete the SQLite edit and core validation/rollback after a browser disconnect.
            tokio::spawn(next.run(req)).await.map_err(internal_err)
        },
    ));
    let protected_api = service_api.merge(tools_api).merge(config_api)
        // Subscriptions
        .route(
            "/subscriptions",
            get(api_list_subscriptions).post(api_save_subscription),
        )
        .route(
            "/subscriptions/template",
            get(api_get_sub_template).put(api_save_sub_template),
        )
        .route(
            "/subscriptions/preview-template",
            post(api_preview_sub_template),
        )
        .route("/subscriptions/{id}/rotate", post(api_rotate_subscription))
        .route("/subscriptions/{id}", delete(api_delete_subscription))
        // Multi-Node Cluster Federation
        .route("/cluster/overview", get(api_cluster_overview))
        .route("/cluster/local", put(api_cluster_save_local))
        .route("/cluster/local/token/rotate", post(api_cluster_rotate_token))
        .route("/cluster/local/token/revoke", post(api_cluster_revoke_token))
        .route("/cluster/nodes", post(api_cluster_save_node))
        .route("/cluster/nodes/test", post(api_cluster_test_node))
        .route("/cluster/sync", post(api_cluster_sync_all))
        .route("/cluster/nodes/{id}/sync", post(api_cluster_sync_one))
        .route("/cluster/nodes/{id}", delete(api_cluster_delete_node))
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
        .route("/auth/me", get(api_me))
        // Read-only cluster federation export (authenticated by Cluster API Token or Admin Session)
        .route("/cluster/export", get(api_cluster_export));

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
    let dns_groups = state.db.list_dns_groups().map_err(internal_err)?;
    let rule_sources = state.db.list_rule_source_groups().map_err(internal_err)?;
    let groups = state.db.list_outbound_groups().map_err(internal_err)?;
    let rules = state.db.list_routing_rules().map_err(internal_err)?;
    let inbounds = state.db.list_inbounds().map_err(internal_err)?;
    let yaml = build_shoes_yaml_full(
        &state.db.data_dir,
        &settings,
        &certs,
        &dns_groups,
        &rule_sources,
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

    let mut sni_counts: std::collections::HashMap<(String, u16), usize> =
        std::collections::HashMap::new();
    for ib in &inbounds {
        if ib.enable && ib.can_share_sni_port() {
            let l = if ib.listen.trim().is_empty() {
                "0.0.0.0".to_string()
            } else {
                ib.listen.trim().to_string()
            };
            *sni_counts.entry((l, ib.port)).or_insert(0) += 1;
        }
    }

    let enriched: Vec<Value> = inbounds
        .into_iter()
        .map(|ib| {
            let active = active_map.get(&ib.tag).copied().unwrap_or(0);
            let shares: Vec<_> = ib
                .clients
                .iter()
                .map(|c| build_client_share_info(&ib, c, &host))
                .collect();
            let sni_shared_count = if ib.enable && ib.can_share_sni_port() {
                let l = if ib.listen.trim().is_empty() {
                    "0.0.0.0".to_string()
                } else {
                    ib.listen.trim().to_string()
                };
                let cnt = sni_counts.get(&(l, ib.port)).copied().unwrap_or(0);
                if cnt >= 2 { cnt } else { 0 }
            } else {
                0
            };
            let mut val = serde_json::to_value(&ib).unwrap_or_else(|_| json!({}));
            val["active_connections"] = json!(active);
            val["shares"] = json!(shares);
            val["share_host"] = json!(host);
            val["multi_user_supported"] = json!(ib.supports_multi_user());
            val["sni_shared_count"] = json!(sni_shared_count);
            val
        })
        .collect();
    ok_json(enriched)
}

async fn api_create_inbound(
    State(state): State<Arc<AppState>>,
    Json(ib): Json<Inbound>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    let created = state.db.create_inbound(ib).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
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
    let _operation = state.proc_mgr.operation.lock().await;
    let prev = state
        .db
        .get_inbound(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Inbound not found"))?;
    let updated = state.db.update_inbound(id, ib).map_err(bad_req)?;
    finish_inbound_edit(&state, prev, updated).await
}

// Callers hold the process operation lock across the edit, validation and rollback.
async fn finish_inbound_edit(state: &AppState, previous: Inbound, updated: Inbound) -> ApiResult {
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        state.db.restore_inbound(previous).map_err(internal_err)?;
        return Err(bad_req(format!("{e:#}")));
    }
    ok_json(updated)
}

async fn delete_config_rows(state: &AppState, table: ConfigTable, ids: &[i64])
    -> Result<usize, (StatusCode, Json<Value>)>
{
    let deleted = state.db.delete_config_rows(table, ids).map_err(internal_err)?;
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        state.db.undo_config_deletion(deleted).map_err(internal_err)?;
        return Err(bad_req(format!("{e:#}")));
    }
    Ok(deleted.affected)
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
    let _operation = state.proc_mgr.operation.lock().await;
    let prev = state
        .db
        .get_inbound(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Inbound not found"))?;
    state
        .db
        .set_inbound_enable(id, req.enable)
        .map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
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
    let _operation = state.proc_mgr.operation.lock().await;
    let mut src = state
        .db
        .get_inbound(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Source inbound not found"))?;

    let exact = req.port.filter(|p| *p > 0);
    let start = exact.unwrap_or_else(|| src.port.saturating_add(1));
    state.db.assign_inbound_port(&mut src, start, exact.is_some()).map_err(bad_req)?;
    let new_port = src.port;

    src.id = 0;
    src.tag = String::new();
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
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        let _ = state.db.delete_inbound(created.id);
        return Err(bad_req(e));
    }
    ok_json(created)
}

async fn api_reset_inbound_traffic(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    state.db.reset_inbound_traffic(id).map_err(bad_req)?;
    ok_json(true)
}

async fn api_reset_all_inbound_traffic(State(state): State<Arc<AppState>>) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    state.db.reset_all_traffic().map_err(bad_req)?;
    ok_json(true)
}

async fn api_delete_inbound(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    delete_config_rows(&state, ConfigTable::Inbounds, &[id]).await?;
    ok_json(true)
}

#[derive(Deserialize)]
struct BatchInboundsReq {
    ids: Vec<i64>,
    action: String, // "enable" | "disable" | "extend_expiry" | "reset_traffic" | "delete"
    #[serde(default)]
    extend_days: Option<i64>,
    #[serde(default)]
    set_expiry_time: Option<i64>,
    #[serde(default)]
    apply_to_clients: bool,
    #[serde(default)]
    re_enable_expired: bool,
}

async fn api_batch_inbounds(
    State(state): State<Arc<AppState>>,
    Json(mut req): Json<BatchInboundsReq>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    if req.ids.is_empty() {
        return Err(bad_req("Please select at least one inbound"));
    }
    let action = req.action.trim().to_ascii_lowercase();
    req.ids.sort_unstable();
    req.ids.dedup();
    if action == "delete" {
        let affected = delete_config_rows(&state, ConfigTable::Inbounds, &req.ids).await?;
        return ok_json(json!({ "affected": affected, "action": action }));
    }

    // Snapshot affected inbounds so we can roll back if `shoes check` rejects the batch change
    let mut snapshots = Vec::new();
    if matches!(action.as_str(), "enable" | "disable") || (action == "extend_expiry" && req.re_enable_expired) {
        for &id in &req.ids {
            if let Some(ib) = state.db.get_inbound(id).map_err(internal_err)? {
                snapshots.push(ib);
            }
        }
    }

    let (affected, needs_reload) = match action.as_str() {
        "enable" => (
            state
                .db
                .batch_set_inbounds_enable(&req.ids, true)
                .map_err(bad_req)?,
            true,
        ),
        "disable" => (
            state
                .db
                .batch_set_inbounds_enable(&req.ids, false)
                .map_err(bad_req)?,
            true,
        ),
        "extend_expiry" => (
            state
                .db
                .batch_extend_inbounds_expiry(
                    &req.ids,
                    req.extend_days,
                    req.set_expiry_time,
                    req.apply_to_clients,
                    req.re_enable_expired,
                )
                .map_err(bad_req)?,
            req.re_enable_expired,
        ),
        "reset_traffic" => (
            state
                .db
                .batch_reset_inbounds_traffic(&req.ids)
                .map_err(bad_req)?,
            false,
        ),
        other => {
            return Err(bad_req(format!("Unknown batch action '{other}'")));
        }
    };

    if needs_reload {
        if let Err(e) = state.proc_mgr.reload_config_locked().await {
            for prev in snapshots {
                state.db.restore_inbound(prev).map_err(internal_err)?;
            }
            return Err(bad_req(e));
        }
    }

    ok_json(json!({ "affected": affected, "action": action }))
}

#[derive(Deserialize)]
struct ImportPreviewReq {
    input: String,
}

async fn api_import_inbounds_preview(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportPreviewReq>,
) -> ApiResult {
    let existing = state.db.list_inbounds().map_err(internal_err)?;
    let preview =
        crate::ops_util::parse_migration_inbounds(&req.input, &existing).map_err(bad_req)?;
    ok_json(preview)
}

#[derive(Deserialize)]
struct ImportApplyReq {
    inbounds: Vec<Inbound>,
    #[serde(default)]
    auto_reassign_ports: bool,
    #[serde(default)]
    disable_on_import: bool,
}

async fn api_import_inbounds_apply(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportApplyReq>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    if req.inbounds.is_empty() {
        return Err(bad_req("No inbounds selected to import"));
    }
    let mut created_ids: Vec<i64> = Vec::new();
    let mut created_items: Vec<Inbound> = Vec::new();

    for mut ib in req.inbounds {
        ib.id = 0;
        ib.tag = String::new();
        ib.up_bytes = 0;
        ib.down_bytes = 0;
        if req.disable_on_import {
            ib.enable = false;
        }
        // If TLS inbound has no certificate source or file path attached, import disabled so `shoes check` won't fail the entire batch
        let missing_tls_cert = ib.stream_settings.security == "tls"
            && !ib.uses_auto_quic_cert()
            && ((ib.stream_settings.tls.cert_mode == "source"
                && ib.stream_settings.tls.certificate_source.trim().is_empty())
                || (ib.stream_settings.tls.cert_mode == "files"
                    && (ib.stream_settings.tls.cert_file.trim().is_empty()
                        || ib.stream_settings.tls.key_file.trim().is_empty())));
        if missing_tls_cert {
            ib.enable = false;
        }

        let created = match state.db.create_inbound(ib.clone()) {
            Ok(c) => c,
            Err(first_err) if req.auto_reassign_ports => {
                let start = if ib.port >= 1024 { ib.port } else { 20000 };
                match state.db.assign_inbound_port(&mut ib, start, false)
                    .and_then(|()| state.db.create_inbound(ib)) {
                    Ok(c) => c,
                    Err(e) => {
                        state.db.batch_delete_inbounds(&created_ids).map_err(internal_err)?;
                        return Err(bad_req(format!(
                            "Failed to import inbound (even after port reassignment): {e} (initial: {first_err})"
                        )));
                    }
                }
            }
            Err(e) => {
                state.db.batch_delete_inbounds(&created_ids).map_err(internal_err)?;
                return Err(bad_req(e));
            }
        };
        created_ids.push(created.id);
        created_items.push(created);
    }

    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        state.db.batch_delete_inbounds(&created_ids).map_err(internal_err)?;
        return Err(bad_req(e));
    }

    ok_json(json!({
        "imported_count": created_items.len(),
        "inbounds": created_items,
    }))
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
    let _operation = state.proc_mgr.operation.lock().await;
    let prev = state.db.get_inbound(id).map_err(internal_err)?.ok_or_else(|| bad_req("Inbound not found"))?;
    let updated = state.db.add_client(id, client).map_err(bad_req)?;
    finish_inbound_edit(&state, prev, updated).await
}

async fn api_update_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<i64>,
    Json(client): Json<ClientRecord>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    let prev = state.db.inbound_for_client(client_id).map_err(bad_req)?;
    let updated = state.db.update_client(client_id, client).map_err(bad_req)?;
    finish_inbound_edit(&state, prev, updated).await
}

async fn api_delete_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<i64>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    let prev = state.db.inbound_for_client(client_id).map_err(bad_req)?;
    let updated = state.db.delete_client(client_id).map_err(bad_req)?;
    finish_inbound_edit(&state, prev, updated).await
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
    let port = state.db.next_available_port(q.start).map_err(bad_req)?;
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

async fn api_keygen_wireguard() -> ApiResult {
    let (priv_k, pub_k, psk) = generate_wireguard_keypair();
    ok_json(json!({
        "private_key": priv_k,
        "public_key": pub_k,
        "preshared_key": psk,
    }))
}

async fn api_keygen_warp() -> ApiResult {
    let profile = register_cloudflare_warp().await.map_err(bad_req)?;
    ok_json(profile)
}

#[derive(Deserialize)]
struct ParseWgConfRequest {
    conf: String,
}

async fn api_parse_wg_conf(Json(req): Json<ParseWgConfRequest>) -> ApiResult {
    let profile = parse_wireguard_conf(&req.conf).map_err(bad_req)?;
    ok_json(profile)
}

#[derive(Deserialize)]
struct VlessEncQuery {
    #[serde(default)]
    auth: String, // "mlkem768" | "x25519"
    #[serde(default)]
    mode: String, // "native" | "xorpub" | "random"
    #[serde(default)]
    rtt: String, // "0rtt" | "1rtt"
    #[serde(default)]
    lifetime: String, // "600s" | "0s"
}

async fn api_keygen_vless_encryption(
    State(state): State<Arc<AppState>>,
    Query(q): Query<VlessEncQuery>,
) -> ApiResult {
    let settings = state.db.get_settings().map_err(internal_err)?;
    let bin = std::path::PathBuf::from(settings.shoes_bin_path.trim());
    if !bin.exists() {
        return Err(bad_req(format!(
            "shoes binary not found at '{}'; install/configure shoes first to generate VLESS encryption keys",
            bin.display()
        )));
    }
    let auth = match q.auth.trim() {
        "x25519" => "x25519",
        _ => "mlkem768",
    };
    let mode = match q.mode.trim() {
        "xorpub" => "xorpub",
        "random" => "random",
        _ => "native",
    };
    let rtt = match q.rtt.trim() {
        "1rtt" => "1rtt",
        _ => "0rtt",
    };
    let lifetime = if q.lifetime.trim().is_empty() {
        "600s"
    } else {
        q.lifetime.trim()
    };

    let output = tokio::process::Command::new(&bin)
        .args([
            "generate-vless-encryption",
            "--auth",
            auth,
            "--mode",
            mode,
            "--rtt",
            rtt,
            "--lifetime",
            lifetime,
        ])
        .output()
        .await
        .map_err(|e| bad_req(format!("failed to execute shoes generate-vless-encryption: {e}")))?;

    if !output.status.success() {
        return Err(bad_req(format!(
            "shoes generate-vless-encryption failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut encryption = String::new();
    let mut decryption = String::new();
    for line in stdout.lines() {
        if let Some(v) = line.trim().strip_prefix("encryption:") {
            encryption = v.trim().to_string();
        } else if let Some(v) = line.trim().strip_prefix("decryption:") {
            decryption = v.trim().to_string();
        }
    }
    if encryption.is_empty() || decryption.is_empty() {
        return Err(bad_req(format!(
            "Unexpected output from shoes generate-vless-encryption: {stdout}"
        )));
    }
    ok_json(json!({
        "encryption": encryption,
        "decryption": decryption,
        "auth": auth,
        "mode": mode,
        "rtt": rtt,
        "lifetime": lifetime,
    }))
}

async fn api_keygen_mldsa65(State(state): State<Arc<AppState>>) -> ApiResult {
    let settings = state.db.get_settings().map_err(internal_err)?;
    let bin = std::path::PathBuf::from(settings.shoes_bin_path.trim());
    if !bin.exists() {
        return Err(bad_req(format!(
            "shoes binary not found at '{}'; install/configure shoes first to generate ML-DSA-65 keys",
            bin.display()
        )));
    }
    let output = tokio::process::Command::new(&bin)
        .arg("generate-reality-mldsa65-keypair")
        .output()
        .await
        .map_err(|e| bad_req(format!("failed to execute shoes generate-reality-mldsa65-keypair: {e}")))?;
    if !output.status.success() {
        return Err(bad_req(format!(
            "shoes generate-reality-mldsa65-keypair failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut seed = String::new();
    let mut verify = String::new();
    for line in stdout.lines() {
        if let Some(v) = line.trim().strip_prefix("mldsa65_seed:") {
            seed = v.trim().to_string();
        } else if let Some(v) = line.trim().strip_prefix("mldsa65_verify:") {
            verify = v.trim().to_string();
        }
    }
    if seed.is_empty() || verify.is_empty() {
        return Err(bad_req(format!(
            "Unexpected output from shoes generate-reality-mldsa65-keypair: {stdout}"
        )));
    }
    ok_json(json!({
        "mldsa65_seed": seed,
        "mldsa65_verify": verify,
    }))
}

#[derive(Deserialize)]
struct MtlsClientQuery {
    #[serde(default)]
    cn: String,
}

async fn api_keygen_mtls_client(Query(q): Query<MtlsClientQuery>) -> ApiResult {
    let (cert_pem, key_pem, fingerprint) =
        crate::crypto_util::generate_mtls_client_cert(&q.cn).map_err(bad_req)?;
    ok_json(json!({
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "fingerprint": fingerprint,
    }))
}

#[derive(Deserialize)]
struct ParseOutboundUriReq {
    uris: String,
}

async fn api_parse_outbound_uri(Json(req): Json<ParseOutboundUriReq>) -> ApiResult {
    let members = crate::ops_util::parse_outbound_share_uris(&req.uris).map_err(bad_req)?;
    ok_json(json!({ "members": members }))
}

#[derive(Deserialize)]
struct ProbeRealityReq {
    #[serde(default)]
    dest: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    targets: Vec<crate::reality_probe::RealityProbeTarget>,
    #[serde(default)]
    use_presets: bool,
    #[serde(default)]
    timeout_ms: u64,
}

async fn api_probe_reality(Json(req): Json<ProbeRealityReq>) -> ApiResult {
    use crate::reality_probe::{
        probe_reality_batch, RealityProbeTarget, DEFAULT_REALITY_CANDIDATES,
    };
    let timeout = std::time::Duration::from_millis(req.timeout_ms.clamp(1500, 6000));
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if !req.dest.trim().is_empty() {
        let key = format!(
            "{}|{}",
            req.dest.trim().to_ascii_lowercase(),
            req.sni.trim().to_ascii_lowercase()
        );
        if seen.insert(key) {
            targets.push(RealityProbeTarget {
                dest: req.dest.trim().to_string(),
                sni: req.sni.trim().to_string(),
            });
        }
    }
    for t in req.targets {
        if t.dest.trim().is_empty() {
            continue;
        }
        let key = format!(
            "{}|{}",
            t.dest.trim().to_ascii_lowercase(),
            t.sni.trim().to_ascii_lowercase()
        );
        if seen.insert(key) {
            targets.push(t);
        }
    }
    if req.use_presets || targets.is_empty() {
        for cand in DEFAULT_REALITY_CANDIDATES {
            let key = format!("{}|", cand.to_ascii_lowercase());
            if seen.insert(key) {
                targets.push(RealityProbeTarget {
                    dest: (*cand).to_string(),
                    sni: String::new(),
                });
            }
        }
    }

    let results = probe_reality_batch(targets, timeout).await;
    ok_json(json!({
        "results": results,
        "candidates": DEFAULT_REALITY_CANDIDATES,
    }))
}

#[derive(Deserialize, Default)]
struct ProbeEgressReq {
    #[serde(default)]
    targets: Vec<crate::egress_probe::EgressProbeTargetReq>,
    #[serde(default)]
    compare_all: bool,
    #[serde(default)]
    timeout_ms: u64,
}

async fn api_probe_egress(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProbeEgressReq>,
) -> ApiResult {
    use crate::egress_probe::{probe_egress_batch, EgressProbeTargetReq};

    let timeout_ms = if req.timeout_ms == 0 {
        8000
    } else {
        req.timeout_ms.clamp(3500, 15_000)
    };
    let timeout = std::time::Duration::from_millis(timeout_ms);

    let mut targets = req.targets;
    if targets.is_empty() {
        targets.push(EgressProbeTargetReq {
            kind: "direct".to_string(),
            group_name: String::new(),
            member_name: String::new(),
            ip_version: "ipv4".to_string(),
        });
        targets.push(EgressProbeTargetReq {
            kind: "direct".to_string(),
            group_name: String::new(),
            member_name: String::new(),
            ip_version: "ipv6".to_string(),
        });
        if req.compare_all {
            let mut groups = state.db.list_outbound_groups().map_err(internal_err)?;
            groups.retain(|g| g.enable);
            groups.sort_by_key(|g| (!g.name.to_ascii_lowercase().contains("warp"), g.id));
            for g in groups.into_iter().take(4) {
                targets.push(EgressProbeTargetReq {
                    kind: "outbound_group".to_string(),
                    group_name: g.name,
                    member_name: String::new(),
                    ip_version: "auto".to_string(),
                });
            }
        }
    }

    let report = probe_egress_batch(state.db.clone(), targets, timeout).await;
    ok_json(report)
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
    let _operation = state.proc_mgr.operation.lock().await;
    let previous = if cert.id > 0 {
        state.db.get_certificate(cert.id).map_err(internal_err)?
    } else {
        None
    };
    let saved = state.db.save_certificate(cert).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        if let Some(prev) = previous {
            state.db.restore_certificate(&prev).map_err(internal_err)?;
        } else {
            state.db.delete_certificate(saved.id).map_err(internal_err)?;
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
    let _operation = state.proc_mgr.operation.lock().await;
    let existing = state
        .db
        .get_certificate(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Certificate not found"))?;

    let inbounds = state.db.list_inbounds().map_err(internal_err)?;
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
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        state.db.restore_certificate(&existing).map_err(internal_err)?;
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
    let _operation = state.proc_mgr.operation.lock().await;
    let previous = if g.id > 0 {
        state.db.get_outbound_group(g.id).map_err(internal_err)?
    } else {
        None
    };
    let saved = state.db.save_outbound_group(g).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        if let Some(prev) = previous {
            let _ = state.db.save_outbound_group(prev);
        } else {
            let _ = state.db.delete_outbound_group(saved.id);
        }
        return Err(bad_req(e));
    }
    ok_json(saved)
}

async fn api_delete_outbound_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    delete_config_rows(&state, ConfigTable::OutboundGroups, &[id]).await?;
    ok_json(true)
}

// ==================== DNS Groups ====================

async fn api_list_dns_groups(State(state): State<Arc<AppState>>) -> ApiResult {
    ok_json(state.db.list_dns_groups().map_err(internal_err)?)
}

async fn api_save_dns_group(
    State(state): State<Arc<AppState>>,
    Json(g): Json<DnsGroupRecord>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    let previous = if g.id > 0 {
        state.db.get_dns_group(g.id).map_err(internal_err)?
    } else {
        None
    };
    let saved = state.db.save_dns_group(g).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        if let Some(prev) = previous {
            let _ = state.db.save_dns_group(prev);
        } else {
            let _ = state.db.delete_dns_group(saved.id);
        }
        return Err(bad_req(e));
    }
    ok_json(saved)
}

async fn api_delete_dns_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    let existing = state
        .db
        .get_dns_group(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("DNS group not found"))?;
    if let Ok(settings) = state.db.get_settings() {
        if settings.core_global.default_dns_group.trim() == existing.name.trim() {
            return Err(bad_req(format!(
                "DNS group '{}' is currently set as global default DNS. Clear default DNS first.",
                existing.name
            )));
        }
    }
    delete_config_rows(&state, ConfigTable::DnsGroups, &[id]).await?;
    ok_json(true)
}

// ==================== Rule Source Groups ====================

async fn api_list_rule_sources(State(state): State<Arc<AppState>>) -> ApiResult {
    ok_json(state.db.list_rule_source_groups().map_err(internal_err)?)
}

async fn api_save_rule_source(
    State(state): State<Arc<AppState>>,
    Json(mut g): Json<RuleSourceGroupRecord>,
) -> ApiResult {
    if g.name.trim().is_empty() {
        return Err(bad_req("Rule source group name must not be empty"));
    }
    if g.items.is_empty() {
        return Err(bad_req(
            "Rule source group must contain at least one URL or local file source",
        ));
    }

    // Download and cache panel-managed remote URLs before taking the process operation lock
    // so slow external downloads do not block inbound edits, Shoes lifecycle, watchdog, or quotas.
    if g.enable {
        let needs_panel_sync = g
            .items
            .iter()
            .any(|item| item.source_type == "url" && item.sync_mode != "shoes_native");
        if needs_panel_sync {
            sync_rule_source_group(&state.db.data_dir, &mut g)
                .await
                .map_err(bad_req)?;
        }
    }

    let _operation = state.proc_mgr.operation.lock().await;
    let previous = if g.id > 0 {
        state.db.get_rule_source_group(g.id).map_err(internal_err)?
    } else {
        None
    };
    let saved = state.db.save_rule_source_group(g).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        if let Some(prev) = previous {
            state.db.save_rule_source_group(prev).map_err(internal_err)?;
        } else {
            state.db.delete_rule_source_group(saved.id).map_err(internal_err)?;
        }
        return Err(bad_req(e));
    }
    ok_json(saved)
}

async fn api_sync_rule_source(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let mut group = state
        .db
        .get_rule_source_group(id)
        .map_err(internal_err)?
        .ok_or_else(|| bad_req("Rule source group not found"))?;
    let initial_sources: Vec<(String, String, String)> = group
        .items
        .iter()
        .map(|i| (i.source_type.clone(), i.sync_mode.clone(), i.url.clone()))
        .collect();
    let changed = sync_rule_source_group(&state.db.data_dir, &mut group)
        .await
        .map_err(bad_req)?;

    let _operation = state.proc_mgr.operation.lock().await;
    let Some(latest) = state.db.get_rule_source_group(id).map_err(internal_err)? else {
        return Err(bad_req("Rule source group not found"));
    };
    let latest_sources: Vec<(String, String, String)> = latest
        .items
        .iter()
        .map(|i| (i.source_type.clone(), i.sync_mode.clone(), i.url.clone()))
        .collect();
    if latest_sources != initial_sources {
        return Err(bad_req(
            "Rule source group was modified while syncing; please retry",
        ));
    }
    state
        .db
        .update_rule_source_items(latest.id, &group.items)
        .map_err(internal_err)?;
    if latest.enable {
        if let Err(e) = state.proc_mgr.reload_config_locked().await {
            state
                .db
                .update_rule_source_items(latest.id, &latest.items)
                .map_err(internal_err)?;
            return Err(bad_req(e));
        }
    }
    group.enable = latest.enable;
    ok_json(json!({ "group": group, "changed": changed }))
}

async fn api_delete_rule_source(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    if delete_config_rows(&state, ConfigTable::RuleSourceGroups, &[id]).await? == 0 {
        return Err(bad_req("Rule source group not found"));
    }
    ok_json(true)
}

async fn api_list_routing_rules(State(state): State<Arc<AppState>>) -> ApiResult {
    ok_json(state.db.list_routing_rules().map_err(internal_err)?)
}

async fn api_save_routing_rule(
    State(state): State<Arc<AppState>>,
    Json(r): Json<RoutingRuleRecord>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    let previous = if r.id > 0 {
        state.db.get_routing_rule(r.id).map_err(internal_err)?
    } else {
        None
    };
    let saved = state.db.save_routing_rule(r).map_err(bad_req)?;
    if let Err(e) = state.proc_mgr.reload_config_locked().await {
        if let Some(prev) = previous {
            let _ = state.db.save_routing_rule(prev);
        } else {
            let _ = state.db.delete_routing_rule(saved.id);
        }
        return Err(bad_req(e));
    }
    ok_json(saved)
}

async fn api_delete_routing_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let _operation = state.proc_mgr.operation.lock().await;
    delete_config_rows(&state, ConfigTable::RoutingRules, &[id]).await?;
    ok_json(true)
}

// ==================== Multi-Node Cluster Federation ====================

fn mask_api_token(tok: &str) -> String {
    let t = tok.trim();
    if t.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = t.chars().collect();
    if chars.len() <= 10 {
        return "••••••••".to_string();
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}••••••{tail}")
}

fn resolve_panel_public_url(
    state: &AppState,
    settings: &PanelSettings,
    headers: &HeaderMap,
) -> String {
    let base_path = state.get_base_path();
    let suffix = if base_path == "/" {
        String::new()
    } else {
        base_path
    };
    if let Some(xfh) = headers
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
        return format!("{proto}://{xfh}{suffix}");
    }
    let host = resolve_share_host(state, settings, headers, None);
    let host_fmt = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    format!("{}://{host_fmt}:{}{suffix}", state.listener_scheme, state.listener_port)
}

async fn api_cluster_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult {
    let token = extract_cluster_token_from_headers(&headers).unwrap_or_default();
    let authorized =
        state.sessions.validate(&token).is_some() || state.db.verify_cluster_api_token(&token);
    if !authorized {
        return Err(err_json(
            StatusCode::UNAUTHORIZED,
            "Invalid or disabled cluster API token",
        ));
    }

    let settings = state.db.get_settings().map_err(internal_err)?;
    let local_cfg = state.db.get_cluster_local_config().map_err(internal_err)?;
    let share_host = resolve_share_host(&state, &settings, &headers, None);
    let shoes = ClusterShoesSummary::from(&state.proc_mgr.status().await);
    let system = ClusterSystemSummary::from(&state.monitor.snapshot());
    let totals = state.db.inbound_totals().map_err(internal_err)?;
    let all_inbounds = state.db.list_inbounds().map_err(internal_err)?;
    let certs = state.db.list_certificates().unwrap_or_default();
    let inbounds: Vec<crate::models::Inbound> = all_inbounds
        .into_iter()
        .filter(|i| i.enable && i.protocol != "portforward")
        .collect();
    let cert_pems = collect_public_cert_pems(&inbounds, &certs);

    ok_json(ClusterExportPayload {
        instance_id: local_cfg.instance_id,
        panel_version: env!("CARGO_PKG_VERSION").to_string(),
        local_name: local_cfg.local_name,
        local_region: local_cfg.local_region,
        local_region_flag: local_cfg.local_region_flag,
        share_host,
        shoes,
        system,
        totals,
        inbounds,
        cert_pems,
    })
}

async fn build_cluster_overview_json(state: &AppState, headers: &HeaderMap) -> Result<Value, (StatusCode, Json<Value>)> {
    let settings = state.db.get_settings().map_err(internal_err)?;
    let local_cfg = state.db.get_cluster_local_config().map_err(internal_err)?;
    let local_shoes = ClusterShoesSummary::from(&state.proc_mgr.status().await);
    let local_sys = ClusterSystemSummary::from(&state.monitor.snapshot());
    let local_totals = state.db.inbound_totals().map_err(internal_err)?;
    let local_share_host = resolve_share_host(state, &settings, headers, None);
    let local_panel_url = resolve_panel_public_url(state, &settings, headers);

    let nodes = state.db.list_cluster_nodes().map_err(internal_err)?;
    let snapshots = state.cluster.get_snapshots();

    let mut nodes_total = 1usize;
    let mut nodes_online = 1usize;
    let mut shoes_running = usize::from(local_shoes.running);
    let mut inbounds_total = local_totals.inbounds_total;
    let mut inbounds_enabled = local_totals.inbounds_enabled;
    let mut clients_total = local_totals.clients_total;
    let mut active_connections = local_sys.active_connections;
    let mut proxy_up_speed = local_sys.proxy_up_speed;
    let mut proxy_down_speed = local_sys.proxy_down_speed;
    let mut net_rx_speed = local_sys.net_rx_speed;
    let mut net_tx_speed = local_sys.net_tx_speed;
    let mut total_up_bytes = local_totals.up_bytes;
    let mut total_down_bytes = local_totals.down_bytes;
    let mut region_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    if !local_cfg.local_region.trim().is_empty() {
        let lbl = if !local_cfg.local_region_flag.trim().is_empty() {
            format!("{} {}", local_cfg.local_region_flag.trim(), local_cfg.local_region.trim())
        } else {
            local_cfg.local_region.trim().to_string()
        };
        *region_counts.entry(lbl).or_insert(0) += 1;
    }

    let mut enriched_nodes = Vec::with_capacity(nodes.len());
    for n in nodes {
        let snap = snapshots.get(&n.id).cloned();
        if n.enable {
            nodes_total += 1;
            if !n.region.trim().is_empty() {
                let lbl = if !n.region_flag.trim().is_empty() {
                    format!("{} {}", n.region_flag.trim(), n.region.trim())
                } else {
                    n.region.trim().to_string()
                };
                *region_counts.entry(lbl).or_insert(0) += 1;
            }
            if let Some(ref s) = snap {
                if s.online {
                    nodes_online += 1;
                    if s.shoes.running {
                        shoes_running += 1;
                    }
                    inbounds_total += s.totals.inbounds_total;
                    inbounds_enabled += s.totals.inbounds_enabled;
                    clients_total += s.totals.clients_total;
                    active_connections += s.system.active_connections;
                    proxy_up_speed = proxy_up_speed.saturating_add(s.system.proxy_up_speed);
                    proxy_down_speed = proxy_down_speed.saturating_add(s.system.proxy_down_speed);
                    net_rx_speed = net_rx_speed.saturating_add(s.system.net_rx_speed);
                    net_tx_speed = net_tx_speed.saturating_add(s.system.net_tx_speed);
                    total_up_bytes = total_up_bytes.saturating_add(s.totals.up_bytes);
                    total_down_bytes = total_down_bytes.saturating_add(s.totals.down_bytes);
                }
            }
        }
        let has_token = !n.api_token.trim().is_empty();
        let token_preview = mask_api_token(&n.api_token);
        let mut sanitized = n.clone();
        sanitized.api_token = String::new();
        enriched_nodes.push(json!({
            "node": sanitized,
            "has_token": has_token,
            "token_preview": token_preview,
            "snapshot": snap,
        }));
    }

    Ok(json!({
        "local": {
            "instance_id": local_cfg.instance_id,
            "local_name": local_cfg.local_name,
            "local_region": local_cfg.local_region,
            "local_region_flag": local_cfg.local_region_flag,
            "api_token": local_cfg.api_token,
            "api_token_enabled": !local_cfg.api_token.trim().is_empty(),
            "panel_version": env!("CARGO_PKG_VERSION"),
            "share_host": local_share_host,
            "panel_url": local_panel_url,
            "shoes": local_shoes,
            "system": local_sys,
            "totals": local_totals,
        },
        "nodes": enriched_nodes,
        "summary": {
            "nodes_total": nodes_total,
            "nodes_online": nodes_online,
            "shoes_running": shoes_running,
            "inbounds_total": inbounds_total,
            "inbounds_enabled": inbounds_enabled,
            "clients_total": clients_total,
            "active_connections": active_connections,
            "proxy_up_speed": proxy_up_speed,
            "proxy_down_speed": proxy_down_speed,
            "net_rx_speed": net_rx_speed,
            "net_tx_speed": net_tx_speed,
            "total_up_bytes": total_up_bytes,
            "total_down_bytes": total_down_bytes,
            "regions": region_counts,
        }
    }))
}

async fn api_cluster_overview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult {
    ok_json(build_cluster_overview_json(&state, &headers).await?)
}

#[derive(Deserialize)]
struct SaveClusterLocalReq {
    #[serde(default)]
    local_name: String,
    #[serde(default)]
    local_region: String,
    #[serde(default)]
    local_region_flag: String,
}

async fn api_cluster_save_local(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SaveClusterLocalReq>,
) -> ApiResult {
    let saved = state
        .db
        .save_cluster_local_identity(&req.local_name, &req.local_region, &req.local_region_flag)
        .map_err(bad_req)?;
    ok_json(saved)
}

async fn api_cluster_rotate_token(State(state): State<Arc<AppState>>) -> ApiResult {
    let token = state.db.rotate_cluster_api_token().map_err(internal_err)?;
    ok_json(json!({ "api_token": token }))
}

async fn api_cluster_revoke_token(State(state): State<Arc<AppState>>) -> ApiResult {
    state.db.revoke_cluster_api_token().map_err(internal_err)?;
    ok_json(true)
}

#[derive(Deserialize)]
struct TestClusterNodeReq {
    #[serde(default)]
    node_id: i64,
    api_url: String,
    #[serde(default)]
    api_token: String,
    #[serde(default)]
    allow_insecure: bool,
}

async fn api_cluster_test_node(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestClusterNodeReq>,
) -> ApiResult {
    let token = if !req.api_token.trim().is_empty() {
        req.api_token.trim().to_string()
    } else if req.node_id > 0 {
        state
            .db
            .get_cluster_node(req.node_id)
            .map_err(internal_err)?
            .map(|n| n.api_token)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let res = state
        .cluster
        .test_connection(&req.api_url, &token, req.allow_insecure)
        .await
        .map_err(bad_req)?;
    ok_json(res)
}

async fn api_cluster_save_node(
    State(state): State<Arc<AppState>>,
    Json(node): Json<ClusterNodeRecord>,
) -> ApiResult {
    let saved = state.db.save_cluster_node(node).map_err(bad_req)?;
    let snapshot = if saved.enable {
        Some(state.cluster.sync_node(&saved).await)
    } else {
        state.cluster.remove_snapshot(saved.id);
        None
    };
    let mut sanitized = saved;
    let has_token = !sanitized.api_token.trim().is_empty();
    let token_preview = mask_api_token(&sanitized.api_token);
    sanitized.api_token = String::new();
    ok_json(json!({
        "node": sanitized,
        "has_token": has_token,
        "token_preview": token_preview,
        "snapshot": snapshot,
    }))
}

async fn api_cluster_sync_all(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult {
    let _ = state.cluster.sync_all_now().await;
    ok_json(build_cluster_overview_json(&state, &headers).await?)
}

async fn api_cluster_sync_one(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let snap = state.cluster.sync_node_by_id(id).await.map_err(bad_req)?;
    ok_json(snap)
}

async fn api_cluster_delete_node(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    state.db.delete_cluster_node(id).map_err(bad_req)?;
    state.cluster.remove_snapshot(id);
    ok_json(true)
}

// ==================== Subscriptions ====================

fn render_subscription_for_state(
    local_inbounds: &[crate::models::Inbound],
    local_certs: &[CertificateRecord],
    local_host: &str,
    local_cfg: &crate::models::ClusterLocalConfig,
    remote_nodes: &[ClusterNodeRecord],
    snapshots: &HashMap<i64, RemoteNodeSnapshot>,
    include_cluster: bool,
    sub_id_filter: &str,
    format: SubFormat,
    template: &SubscriptionTemplateConfig,
) -> crate::sub_gen::SubscriptionPayload {
    let now = chrono::Utc::now().timestamp_millis();
    let usable_remotes: Vec<(&ClusterNodeRecord, &RemoteNodeSnapshot, String)> = if include_cluster {
        remote_nodes
            .iter()
            .filter(|n| n.enable && n.include_in_sub)
            .filter_map(|n| {
                let snap = snapshots.get(&n.id)?;
                if snap.has_usable_inbounds(now) {
                    Some((n, snap, effective_node_prefix(n)))
                } else {
                    None
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let local_prefix = if !usable_remotes.is_empty() && !local_cfg.local_name.trim().is_empty() {
        let flag = local_cfg.local_region_flag.trim();
        if !flag.is_empty() {
            format!("{flag} {}", local_cfg.local_name.trim())
        } else {
            local_cfg.local_name.trim().to_string()
        }
    } else {
        String::new()
    };

    let mut sources = Vec::with_capacity(1 + usable_remotes.len());
    sources.push(SubSourceNode {
        region: local_cfg.local_region.trim(),
        region_flag: local_cfg.local_region_flag.trim(),
        prefix: local_prefix.as_str(),
        host: local_host,
        inbounds: local_inbounds,
        certs: local_certs,
        cert_pems: None,
    });
    for (node, snap, prefix) in &usable_remotes {
        sources.push(SubSourceNode {
            region: node.region.trim(),
            region_flag: node.region_flag.trim(),
            prefix: prefix.as_str(),
            host: snap.share_host.as_str(),
            inbounds: &snap.inbounds,
            certs: &[],
            cert_pems: Some(&snap.cert_pems),
        });
    }

    generate_aggregated_subscription(&sources, sub_id_filter, format, template)
}

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
        .map(|(s, local_count)| {
            let remote_count = if s.include_cluster {
                state.cluster.count_remote_sub_nodes(&s.sub_id)
            } else {
                0
            };
            let sub_url = format!("{base_url}/sub/{}", s.token);
            let mut v = serde_json::to_value(&s).unwrap_or_else(|_| json!({}));
            v["local_node_count"] = json!(local_count);
            v["remote_node_count"] = json!(remote_count);
            v["node_count"] = json!(local_count + remote_count);
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

async fn api_get_sub_template(State(state): State<Arc<AppState>>) -> ApiResult {
    let settings = state.db.get_settings().map_err(internal_err)?;
    ok_json(settings.sub_template)
}

async fn api_save_sub_template(
    State(state): State<Arc<AppState>>,
    Json(tpl): Json<SubscriptionTemplateConfig>,
) -> ApiResult {
    let saved = state.db.save_sub_template(&tpl).map_err(bad_req)?;
    ok_json(saved)
}

fn default_true_val() -> bool {
    true
}

#[derive(Deserialize)]
struct PreviewSubTemplateReq {
    #[serde(default)]
    sub_id: String,
    #[serde(default = "default_true_val")]
    include_cluster: bool,
    template: SubscriptionTemplateConfig,
}

async fn api_preview_sub_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PreviewSubTemplateReq>,
) -> ApiResult {
    if req.include_cluster {
        state.cluster.ensure_fresh_for_subscription(30_000).await;
    }
    let inbounds = state.db.list_inbounds().map_err(internal_err)?;
    let certs = state.db.list_certificates().unwrap_or_default();
    let settings = state.db.get_settings().map_err(internal_err)?;
    let local_cfg = state.db.get_cluster_local_config().unwrap_or_default();
    let remote_nodes = state.db.list_cluster_nodes().unwrap_or_default();
    let snapshots = state.cluster.get_snapshots();
    let host = resolve_share_host(&state, &settings, &headers, None);
    let sub_id = if req.sub_id.trim().is_empty() {
        "all"
    } else {
        req.sub_id.trim()
    };
    let clash = render_subscription_for_state(
        &inbounds,
        &certs,
        &host,
        &local_cfg,
        &remote_nodes,
        &snapshots,
        req.include_cluster,
        sub_id,
        SubFormat::ClashYaml,
        &req.template,
    );
    let singbox = render_subscription_for_state(
        &inbounds,
        &certs,
        &host,
        &local_cfg,
        &remote_nodes,
        &snapshots,
        req.include_cluster,
        sub_id,
        SubFormat::SingBoxJson,
        &req.template,
    );
    ok_json(json!({
        "clash_yaml": clash.body,
        "singbox_json": singbox.body,
    }))
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
    let include_cluster = match query.get("cluster").map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("0" | "false" | "no" | "off") => false,
        Some("1" | "true" | "yes" | "on") => true,
        _ => sub.include_cluster,
    };
    if include_cluster {
        state.cluster.ensure_fresh_for_subscription(30_000).await;
    }

    let Ok(inbounds) = state.db.list_inbounds() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
    };
    let certs = state.db.list_certificates().unwrap_or_default();
    let Ok(settings) = state.db.get_settings() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Settings error").into_response();
    };
    let local_cfg = state.db.get_cluster_local_config().unwrap_or_default();
    let remote_nodes = if include_cluster {
        state.db.list_cluster_nodes().unwrap_or_default()
    } else {
        Vec::new()
    };
    let snapshots = if include_cluster {
        state.cluster.get_snapshots()
    } else {
        HashMap::new()
    };

    let host = resolve_share_host(
        &state,
        &settings,
        &headers,
        query.get("host").map(String::as_str),
    );
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok());
    let fmt = SubFormat::detect(query.get("format").map(String::as_str), ua);

    let mut effective_tpl = settings.sub_template.clone();
    if let Some(q_tpl) = query
        .get("template")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| matches!(s.as_str(), "minimal" | "global_direct" | "bypass_cn" | "streaming"))
    {
        effective_tpl.preset = q_tpl;
    } else if !sub.template.trim().is_empty() {
        effective_tpl.preset = sub.template.trim().to_ascii_lowercase();
    }
    if let Some(rg) = query.get("region_groups").map(|s| s.trim().to_ascii_lowercase()) {
        if matches!(rg.as_str(), "0" | "false" | "no" | "off") {
            effective_tpl.enable_region_groups = false;
        } else if matches!(rg.as_str(), "1" | "true" | "yes" | "on") {
            effective_tpl.enable_region_groups = true;
        }
    }

    let payload = render_subscription_for_state(
        &inbounds,
        &certs,
        &host,
        &local_cfg,
        &remote_nodes,
        &snapshots,
        include_cluster,
        &sub.sub_id,
        fmt,
        &effective_tpl,
    );

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

async fn restore_and_apply(state: Arc<AppState>, bytes: Vec<u8>) -> ApiResult {
    tokio::spawn(async move {
        let _operation = state.proc_mgr.operation.lock().await;
        let db = state.db.clone();
        let pre_backup = tokio::task::spawn_blocking(move || db.restore_from_bytes(&bytes))
            .await.map_err(internal_err)?.map_err(bad_req)?;
        apply_post_restore(&state, pre_backup).await
    }).await.map_err(internal_err)?
}

async fn apply_post_restore(state: &AppState, pre_backup: String) -> ApiResult {
    state.sessions.revoke_all();
    if let Ok(settings) = state.db.get_settings() {
        state.set_base_path(&settings.panel_base_path);
    }
    // Reload shoes config with restored inbounds/certs/routing (log warning if shoes bin missing)
    let reload_note = match state.proc_mgr.reload_config_locked().await {
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    };
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
    restore_and_apply(state, bytes).await
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
    restore_and_apply(state, bytes).await
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

#[cfg(test)]
#[tokio::test]
async fn rejected_config_mutations_restore_original_rows_through_http() -> anyhow::Result<()> {
    use crate::{db::Database, monitor::RuntimeMonitor, process::ShoesProcessManager};
    use tower::ServiceExt;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir()?;
    let db = Arc::new(Database::open(&dir.path().join("panel.db"), dir.path())?);
    let dns = db.save_dns_group(serde_json::from_value(json!({"name":"saved-dns"}))?)?;
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost".to_string()])?;
    let cert_path = dir.path().join("certs").join("saved-cert.crt");
    let key_path = dir.path().join("certs").join("saved-cert.key");
    write_cert_and_key_atomic(&cert_path, &key_path, &cert_pem, &key_pem)?;
    let cert = db.save_certificate(serde_json::from_value(json!({
        "name": "saved-cert",
        "cert_type": "files",
        "cert_file": cert_path.to_string_lossy().replace('\\', "/"),
        "key_file": key_path.to_string_lossy().replace('\\', "/"),
        "domains": ["localhost"]
    }))?)?;
    let ib = db.create_inbound(serde_json::from_value(json!({
        "protocol":"anytls","remark":"saved-inbound","port":21000,
        "clients":[{"name":"one","password":"one"},{"name":"two","password":"two"}]
    }))?)?;
    db.set_setting_kv("shoes_extra_yaml", "- [")?;
    let manager = ShoesProcessManager::new(db.clone());
    let monitor = RuntimeMonitor::new(db.clone(), manager.clone());
    let state = AppState::new(db.clone(), manager, monitor, &db.get_settings()?);
    let token = state.sessions.create_session("admin", 1);
    let app = build_inner_router(state);
    for (method, path, body) in [
        ("DELETE", format!("/api/dns-groups/{}", dns.id), Value::Null),
        ("DELETE", format!("/api/certificates/{}", cert.id), Value::Null),
        ("POST", "/api/certificates/self-signed".to_owned(), json!({"name":"rejected-cert","domains":["localhost"]})),
        ("DELETE", format!("/api/clients/{}", ib.clients[0].id), Value::Null),
        ("POST", format!("/api/inbounds/{}/clients", ib.id), json!({"name":"new","password":"new"})),
        ("POST", "/api/inbounds/batch".to_owned(), json!({"action":"delete","ids":[ib.id]})),
    ] {
        let req = Request::builder().method(method).uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))?;
        assert_eq!(app.clone().oneshot(req).await?.status(), StatusCode::BAD_REQUEST);
        assert_eq!(serde_json::to_value(db.get_inbound(ib.id)?)?, serde_json::to_value(&ib)?);
        assert_eq!(serde_json::to_value(db.get_dns_group(dns.id)?)?, serde_json::to_value(&dns)?);
        assert_eq!(serde_json::to_value(db.list_certificates()?)?, serde_json::to_value([&cert])?);
    }
    Ok(())
}

#[cfg(test)]
#[tokio::test]
async fn rule_source_remote_sync_does_not_hold_operation_lock() -> anyhow::Result<()> {
    use crate::{db::Database, monitor::RuntimeMonitor, process::ShoesProcessManager};
    use std::time::Duration;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir()?;
    let db = Arc::new(Database::open(&dir.path().join("panel.db"), dir.path())?);
    db.set_setting_kv("shoes_bin_path", "")?;
    let manager = ShoesProcessManager::new(db.clone());
    let monitor = RuntimeMonitor::new(db.clone(), manager.clone());
    let state = AppState::new(db.clone(), manager.clone(), monitor, &db.get_settings()?);
    let token = state.sessions.create_session("admin", 1);
    let app = build_inner_router(state);

    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let s_flag = started.clone();
    let r_flag = release.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let rule_url = format!("http://{}/rules.txt", listener.local_addr()?);
    let mock = Router::new().route(
        "/rules.txt",
        get(move || {
            let s = s_flag.clone();
            let r = r_flag.clone();
            async move {
                s.notify_one();
                r.notified().await;
                "+.example.com\n"
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, mock).await });

    // 1. POST /api/rule-sources must not hold operation lock while downloading
    let save_req = Request::builder()
        .method("POST")
        .uri("/api/rule-sources")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "name": "remote-test",
                "enable": true,
                "items": [{
                    "source_type": "url",
                    "sync_mode": "panel",
                    "url": rule_url,
                    "format": "mihomo_text"
                }]
            })
            .to_string(),
        ))?;
    let save_task = tokio::spawn({
        let app = app.clone();
        async move { app.oneshot(save_req).await }
    });
    tokio::time::timeout(Duration::from_secs(5), started.notified()).await?;
    let guard = manager
        .operation
        .try_lock()
        .expect("operation lock must not be held during rule source download on save");
    drop(guard);
    release.notify_one();
    assert_eq!(save_task.await??.status(), StatusCode::OK);

    let group_id = db.list_rule_source_groups()?[0].id;

    // 2. POST /api/rule-sources/{id}/sync must not hold operation lock while downloading
    let sync_req = Request::builder()
        .method("POST")
        .uri(format!("/api/rule-sources/{group_id}/sync"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;
    let sync_task = tokio::spawn({
        let app = app.clone();
        async move { app.oneshot(sync_req).await }
    });
    tokio::time::timeout(Duration::from_secs(5), started.notified()).await?;
    let guard = manager
        .operation
        .try_lock()
        .expect("operation lock must not be held during rule source download on sync");
    drop(guard);
    release.notify_one();
    assert_eq!(sync_task.await??.status(), StatusCode::OK);

    server.abort();
    Ok(())
}

#[cfg(test)]
#[tokio::test]
async fn egress_probe_http_endpoint_handles_unknown_group_gracefully() -> anyhow::Result<()> {
    use crate::{db::Database, monitor::RuntimeMonitor, process::ShoesProcessManager};
    use tower::ServiceExt;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir()?;
    let db = Arc::new(Database::open(&dir.path().join("panel.db"), dir.path())?);
    db.set_setting_kv("shoes_bin_path", "")?;
    let manager = ShoesProcessManager::new(db.clone());
    let monitor = RuntimeMonitor::new(db.clone(), manager.clone());
    let state = AppState::new(db.clone(), manager, monitor, &db.get_settings()?);
    let token = state.sessions.create_session("admin", 1);
    let app = build_inner_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/tools/probe-egress")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "targets": [{
                    "kind": "outbound_group",
                    "group_name": "nonexistent-warp",
                    "ip_version": "auto"
                }],
                "timeout_ms": 4000
            })
            .to_string(),
        ))?;
    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["reports"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(body["data"]["reports"][0]["ok"], false);
    assert!(body["data"]["reports"][0]["error"]
        .as_str()
        .unwrap_or("")
        .contains("shoes binary not found"));
    Ok(())
}

#[cfg(test)]
#[tokio::test]
async fn cluster_federation_and_regional_aggregated_subscription_e2e() -> anyhow::Result<()> {
    use crate::{db::Database, monitor::RuntimeMonitor, process::ShoesProcessManager};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use tower::ServiceExt;

    let _ = rustls::crypto::ring::default_provider().install_default();

    // Helper to build an isolated shoes-panel instance with 1 VLESS REALITY inbound + traffic
    async fn spawn_child_node(
        name: &str,
        region: &str,
        flag: &str,
        share_host: &str,
        port: u16,
        up: u64,
        down: u64,
    ) -> anyhow::Result<(
        tempfile::TempDir,
        String,
        String,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let dir = tempfile::tempdir()?;
        let db = Arc::new(Database::open(&dir.path().join("panel.db"), dir.path())?);
        db.set_setting_kv("shoes_bin_path", "")?;
        db.set_setting_kv("public_host", share_host)?;
        db.save_cluster_local_identity(name, region, flag)?;
        let cluster_token = db.rotate_cluster_api_token()?;
        let (priv_k, pub_k) = generate_reality_keypair();
        let ib = db.create_inbound(serde_json::from_value(json!({
            "protocol": "vless",
            "remark": format!("{region}-Reality"),
            "port": port,
            "stream_settings": {
                "network": "tcp",
                "security": "reality",
                "reality": {
                    "sni": "www.microsoft.com",
                    "dest": "www.microsoft.com:443",
                    "private_key": priv_k,
                    "public_key": pub_k,
                    "short_ids": ["0123456789abcdef"],
                    "vision": true
                }
            },
            "clients": [{ "name": "alice", "uuid": generate_uuid(), "sub_id": "default" }]
        }))?)?;
        db.add_traffic_deltas(&HashMap::from([(ib.tag, (up, down))]), None)?;

        let mgr = ShoesProcessManager::new(db.clone());
        let mon = RuntimeMonitor::new(db.clone(), mgr.clone());
        let state = AppState::new(db.clone(), mgr, mon, &db.get_settings()?);
        let app = build_inner_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let srv = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok((dir, url, cluster_token, srv))
    }

    let (_hk_dir, hk_url, hk_token, hk_srv) =
        spawn_child_node("HK-Edge", "HK", "🇭🇰", "hk.example.com", 20443, 1000, 2000).await?;
    let (_jp_dir, jp_url, jp_token, jp_srv) =
        spawn_child_node("JP-Tokyo", "JP", "🇯🇵", "jp.example.com", 21443, 3000, 4000).await?;

    // Verify Cluster API Token is strictly read-only (cannot access admin endpoints like /api/settings)
    let raw_http = reqwest::Client::builder().no_proxy().build()?;
    let admin_status = raw_http
        .get(format!("{hk_url}/api/settings"))
        .bearer_auth(&hk_token)
        .send()
        .await?
        .status();
    assert_eq!(admin_status, reqwest::StatusCode::UNAUTHORIZED);

    // Master node (US)
    let master_dir = tempfile::tempdir()?;
    let master_db = Arc::new(Database::open(
        &master_dir.path().join("panel.db"),
        master_dir.path(),
    )?);
    master_db.set_setting_kv("shoes_bin_path", "")?;
    master_db.set_setting_kv("public_host", "us.example.com")?;
    master_db.save_cluster_local_identity("US-Master", "US", "🇺🇸")?;
    let mut tpl = master_db.get_settings()?.sub_template;
    tpl.preset = "streaming".to_string();
    tpl.enable_region_groups = true;
    master_db.save_sub_template(&tpl)?;

    let (m_priv, m_pub) = generate_reality_keypair();
    let master_ib = master_db.create_inbound(serde_json::from_value(json!({
        "protocol": "vless",
        "remark": "US-Reality",
        "port": 22443,
        "stream_settings": {
            "network": "tcp",
            "security": "reality",
            "reality": {
                "sni": "www.microsoft.com",
                "dest": "www.microsoft.com:443",
                "private_key": m_priv,
                "public_key": m_pub,
                "short_ids": ["abcdef0123456789"],
                "vision": true
            }
        },
        "clients": [{ "name": "alice", "uuid": generate_uuid(), "sub_id": "default" }]
    }))?)?;
    master_db.add_traffic_deltas(&HashMap::from([(master_ib.tag, (500, 600))]), None)?;

    let m_mgr = ShoesProcessManager::new(master_db.clone());
    let m_mon = RuntimeMonitor::new(master_db.clone(), m_mgr.clone());
    let m_state = AppState::new(master_db.clone(), m_mgr, m_mon, &master_db.get_settings()?);
    let admin_tok = m_state.sessions.create_session("admin", 1);
    let app = build_inner_router(m_state.clone());

    // 1. Test connection to HK child node before saving
    let test_req = Request::builder()
        .method("POST")
        .uri("/api/cluster/nodes/test")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "api_url": hk_url, "api_token": hk_token }).to_string(),
        ))?;
    let test_resp = app.clone().oneshot(test_req).await?;
    assert_eq!(test_resp.status(), StatusCode::OK);
    let test_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(test_resp.into_body(), 1024 * 1024).await?)?;
    assert_eq!(test_json["data"]["share_host"], "hk.example.com");
    assert_eq!(test_json["data"]["local_region"], "HK");

    // 2. Mount HK and JP remote nodes via POST /api/cluster/nodes
    for (name, region, flag, url, tok) in [
        ("HK-Edge", "HK", "🇭🇰", &hk_url, &hk_token),
        ("JP-Tokyo", "JP", "🇯🇵", &jp_url, &jp_token),
    ] {
        let save_req = Request::builder()
            .method("POST")
            .uri("/api/cluster/nodes")
            .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "name": name,
                    "region": region,
                    "region_flag": flag,
                    "api_url": url,
                    "api_token": tok,
                    "enable": true,
                    "include_in_sub": true
                })
                .to_string(),
            ))?;
        let resp = app.clone().oneshot(save_req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 3. Overview aggregates all 3 VPS nodes (online count, inbounds, cumulative traffic)
    let ov_req = Request::builder()
        .method("GET")
        .uri("/api/cluster/overview")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .body(Body::empty())?;
    let ov_resp = app.clone().oneshot(ov_req).await?;
    assert_eq!(ov_resp.status(), StatusCode::OK);
    let ov_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(ov_resp.into_body(), 1024 * 1024).await?)?;
    assert_eq!(ov_json["data"]["summary"]["nodes_total"], 3);
    assert_eq!(ov_json["data"]["summary"]["nodes_online"], 3);
    assert_eq!(ov_json["data"]["summary"]["inbounds_enabled"], 3);
    assert_eq!(ov_json["data"]["summary"]["total_up_bytes"], 4500);
    assert_eq!(ov_json["data"]["summary"]["total_down_bytes"], 6600);
    // Remote API tokens must never be returned raw in overview
    assert_eq!(ov_json["data"]["nodes"][0]["node"]["api_token"], "");
    assert_eq!(ov_json["data"]["nodes"][0]["has_token"], true);

    // 4. Fetch unified subscription in Clash YAML, sing-box JSON, and v2ray Base64
    let sub_token = master_db.list_subscriptions()?[0].token.clone();

    let clash_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/sub/{sub_token}?format=clash"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(clash_resp.status(), StatusCode::OK);
    let userinfo = clash_resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(userinfo.contains("upload=4500; download=6600"), "userinfo={userinfo}");
    let clash_text =
        String::from_utf8(axum::body::to_bytes(clash_resp.into_body(), 2 * 1024 * 1024).await?.to_vec())?;
    let clash_doc: serde_yaml::Value = serde_yaml::from_str(&clash_text)?;
    let proxies = clash_doc["proxies"].as_sequence().unwrap();
    assert_eq!(proxies.len(), 3);
    let servers: Vec<&str> = proxies
        .iter()
        .filter_map(|p| p["server"].as_str())
        .collect();
    assert!(servers.contains(&"us.example.com"));
    assert!(servers.contains(&"hk.example.com"));
    assert!(servers.contains(&"jp.example.com"));

    let pgroups = clash_doc["proxy-groups"].as_sequence().unwrap();
    let gnames: Vec<&str> = pgroups
        .iter()
        .filter_map(|g| g["name"].as_str())
        .collect();
    assert!(gnames.contains(&"🇭🇰 香港"), "groups={gnames:?}");
    assert!(gnames.contains(&"🇯🇵 日本"), "groups={gnames:?}");
    assert!(gnames.contains(&"🇺🇸 美国"), "groups={gnames:?}");
    let ai_group = pgroups.iter().find(|g| g["name"] == "🤖 AI").unwrap();
    let ai_members: Vec<&str> = ai_group["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(ai_members.contains(&"🇺🇸 美国"));
    assert!(ai_members.contains(&"🇯🇵 日本"));

    // sing-box JSON regional urltest groups
    let sb_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/sub/{sub_token}?format=singbox"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(sb_resp.status(), StatusCode::OK);
    let sb_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(sb_resp.into_body(), 2 * 1024 * 1024).await?)?;
    let outbounds = sb_json["outbounds"].as_array().unwrap();
    assert!(outbounds
        .iter()
        .any(|o| o["tag"] == "🇭🇰 香港" && o["type"] == "urltest"));
    assert!(outbounds
        .iter()
        .any(|o| o["tag"] == "🇯🇵 日本" && o["type"] == "urltest"));
    assert!(outbounds
        .iter()
        .any(|o| o["tag"] == "🇺🇸 美国" && o["type"] == "urltest"));

    // v2ray Base64 merges all 3 VPS URIs, while ?cluster=0 restricts to local node only
    let v2_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/sub/{sub_token}?format=v2ray"))
                .body(Body::empty())?,
        )
        .await?;
    let v2_b64 = String::from_utf8(axum::body::to_bytes(v2_resp.into_body(), 1024 * 1024).await?.to_vec())?;
    let v2_plain = String::from_utf8(STANDARD.decode(v2_b64.trim())?)?;
    assert_eq!(v2_plain.lines().count(), 3);
    assert!(v2_plain.contains("hk.example.com:20443"));
    assert!(v2_plain.contains("jp.example.com:21443"));
    assert!(v2_plain.contains("us.example.com:22443"));

    let local_only_resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/sub/{sub_token}?format=raw&cluster=0"))
                .body(Body::empty())?,
        )
        .await?;
    let local_only_txt = String::from_utf8(
        axum::body::to_bytes(local_only_resp.into_body(), 1024 * 1024)
            .await?
            .to_vec(),
    )?;
    assert_eq!(local_only_txt.lines().count(), 1);
    assert!(local_only_txt.contains("us.example.com:22443"));

    hk_srv.abort();
    jp_srv.abort();
    Ok(())
}
