export function getApiBase() {
  const bp = typeof window !== 'undefined' && window.__SHOES_BASE__ ? window.__SHOES_BASE__ : '/';
  const trimmed = bp.replace(/\/+$/, '');
  return `${trimmed}/api`;
}

let unauthorizedHandler = null;
export function onUnauthorized(fn) {
  unauthorizedHandler = fn;
}

export async function apiFetch(path, options = {}) {
  const url = `${getApiBase()}${path.startsWith('/') ? path : `/${path}`}`;
  const headers = { ...(options.headers || {}) };
  const token = localStorage.getItem('shoes_panel_token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }
  const resp = await fetch(url, {
    credentials: 'same-origin',
    ...options,
    headers,
  });
  if (resp.status === 401 && !path.startsWith('/auth/login')) {
    if (unauthorizedHandler) unauthorizedHandler();
    throw new Error('Unauthorized');
  }
  const json = await resp.json().catch(() => ({ ok: false, error: `HTTP ${resp.status}` }));
  if (!resp.ok || json.ok === false) {
    throw new Error(json.error || `Request failed (${resp.status})`);
  }
  return json.data;
}

export const api = {
  login: (username, password) => apiFetch('/auth/login', { method: 'POST', body: { username, password } }),
  logout: () => apiFetch('/auth/logout', { method: 'POST' }),
  me: () => apiFetch('/auth/me'),

  status: () => apiFetch('/status'),
  dailyTraffic: () => apiFetch('/traffic/daily'),
  coreHistory: () => apiFetch('/status/history'),
  shoesStart: () => apiFetch('/shoes/start', { method: 'POST' }),
  shoesStop: () => apiFetch('/shoes/stop', { method: 'POST' }),
  shoesRestart: () => apiFetch('/shoes/restart', { method: 'POST' }),
  shoesReload: () => apiFetch('/shoes/reload', { method: 'POST' }),
  shoesLogs: (since = 0, limit = 300) => apiFetch(`/shoes/logs?since=${since}&limit=${limit}`),
  shoesClearLogs: () => apiFetch('/shoes/logs/clear', { method: 'POST' }),
  shoesConfigPreview: () => apiFetch('/shoes/config-preview'),

  clashConnections: () => apiFetch('/clash/connections'),
  clashCloseAll: () => apiFetch('/clash/connections', { method: 'DELETE' }),
  clashCloseOne: (id) => apiFetch(`/clash/connections/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  clashProxies: () => apiFetch('/clash/proxies'),
  clashSelectProxy: (group, name) =>
    apiFetch(`/clash/proxies/${encodeURIComponent(group)}`, { method: 'PUT', body: { name } }),
  clashDelay: (kind, name) =>
    apiFetch(`/clash/delay?kind=${encodeURIComponent(kind)}&name=${encodeURIComponent(name)}`),

  listInbounds: () => apiFetch('/inbounds'),
  createInbound: (payload) => apiFetch('/inbounds', { method: 'POST', body: payload }),
  batchInbounds: (payload) => apiFetch('/inbounds/batch', { method: 'POST', body: payload }),
  importInboundsPreview: (input) =>
    apiFetch('/inbounds/import/preview', { method: 'POST', body: { input } }),
  importInboundsApply: (payload) =>
    apiFetch('/inbounds/import/apply', { method: 'POST', body: payload }),
  updateInbound: (id, payload) => apiFetch(`/inbounds/${id}`, { method: 'PUT', body: payload }),
  toggleInbound: (id, enable) => apiFetch(`/inbounds/${id}/toggle`, { method: 'POST', body: { enable } }),
  cloneInbound: (id, payload = {}) => apiFetch(`/inbounds/${id}/clone`, { method: 'POST', body: payload }),
  resetInboundTraffic: (id) => apiFetch(`/inbounds/${id}/reset-traffic`, { method: 'POST' }),
  resetAllTraffic: () => apiFetch('/inbounds/reset-all-traffic', { method: 'POST' }),
  deleteInbound: (id) => apiFetch(`/inbounds/${id}`, { method: 'DELETE' }),
  inboundShare: (id, host = '') =>
    apiFetch(`/inbounds/${id}/share${host ? `?host=${encodeURIComponent(host)}` : ''}`),

  addClient: (inboundId, payload) =>
    apiFetch(`/inbounds/${inboundId}/clients`, { method: 'POST', body: payload }),
  updateClient: (clientId, payload) =>
    apiFetch(`/clients/${clientId}`, { method: 'PUT', body: payload }),
  deleteClient: (clientId) => apiFetch(`/clients/${clientId}`, { method: 'DELETE' }),
  nextPort: (start = 20000) => apiFetch(`/next-port?start=${start}`),

  genUuid: () => apiFetch('/keygen/uuid'),
  genReality: () => apiFetch('/keygen/reality'),
  genSs2022: (cipher) => apiFetch(`/keygen/ss2022?cipher=${encodeURIComponent(cipher)}`),
  genRandom: (len = 20) => apiFetch(`/keygen/random?len=${len}`),
  genWireguard: () => apiFetch('/keygen/wireguard'),
  registerWarp: () => apiFetch('/keygen/warp', { method: 'POST' }),
  parseWgConf: (conf) => apiFetch('/keygen/parse-wg-conf', { method: 'POST', body: { conf } }),
  genVlessEncryption: ({ auth = 'mlkem768', mode = 'native', rtt = '0rtt', lifetime = '600s' } = {}) =>
    apiFetch(
      `/keygen/vless-encryption?auth=${encodeURIComponent(auth)}&mode=${encodeURIComponent(mode)}&rtt=${encodeURIComponent(rtt)}&lifetime=${encodeURIComponent(lifetime)}`
    ),
  genMldsa65: () => apiFetch('/keygen/mldsa65'),
  genMtlsClient: (cn = '') =>
    apiFetch(`/keygen/mtls-client${cn ? `?cn=${encodeURIComponent(cn)}` : ''}`),
  probeReality: (payload) => apiFetch('/tools/probe-reality', { method: 'POST', body: payload }),

  listCerts: () => apiFetch('/certificates'),
  acmeMeta: (directory_url = '') =>
    apiFetch(
      `/certificates/acme-meta${directory_url ? `?directory_url=${encodeURIComponent(directory_url)}` : ''}`
    ),
  saveCert: (payload) => apiFetch('/certificates', { method: 'POST', body: payload }),
  uploadCert: (payload) => apiFetch('/certificates/upload', { method: 'POST', body: payload }),
  selfSignedCert: (payload) => apiFetch('/certificates/self-signed', { method: 'POST', body: payload }),
  issueIpCert: (payload) => apiFetch('/certificates/issue-ip', { method: 'POST', body: payload }),
  renewCert: (id) => apiFetch(`/certificates/${id}/renew`, { method: 'POST' }),
  applyPanelHttps: (id) => apiFetch(`/certificates/${id}/apply-panel-https`, { method: 'POST' }),
  deleteCert: (id) => apiFetch(`/certificates/${id}`, { method: 'DELETE' }),

  listOutboundGroups: () => apiFetch('/outbound-groups'),
  saveOutboundGroup: (payload) => apiFetch('/outbound-groups', { method: 'POST', body: payload }),
  parseOutboundUri: (uris) => apiFetch('/outbound-groups/parse-uri', { method: 'POST', body: { uris } }),
  deleteOutboundGroup: (id) => apiFetch(`/outbound-groups/${id}`, { method: 'DELETE' }),

  listDnsGroups: () => apiFetch('/dns-groups'),
  saveDnsGroup: (payload) => apiFetch('/dns-groups', { method: 'POST', body: payload }),
  deleteDnsGroup: (id) => apiFetch(`/dns-groups/${id}`, { method: 'DELETE' }),

  listRuleSources: () => apiFetch('/rule-sources'),
  saveRuleSource: (payload) => apiFetch('/rule-sources', { method: 'POST', body: payload }),
  syncRuleSource: (id) => apiFetch(`/rule-sources/${id}/sync`, { method: 'POST' }),
  deleteRuleSource: (id) => apiFetch(`/rule-sources/${id}`, { method: 'DELETE' }),

  listRoutingRules: () => apiFetch('/routing-rules'),
  saveRoutingRule: (payload) => apiFetch('/routing-rules', { method: 'POST', body: payload }),
  deleteRoutingRule: (id) => apiFetch(`/routing-rules/${id}`, { method: 'DELETE' }),

  listSubscriptions: () => apiFetch('/subscriptions'),
  saveSubscription: (payload) => apiFetch('/subscriptions', { method: 'POST', body: payload }),
  getSubTemplate: () => apiFetch('/subscriptions/template'),
  saveSubTemplate: (payload) => apiFetch('/subscriptions/template', { method: 'PUT', body: payload }),
  previewSubTemplate: (payload) =>
    apiFetch('/subscriptions/preview-template', { method: 'POST', body: payload }),
  rotateSubscription: (id) => apiFetch(`/subscriptions/${id}/rotate`, { method: 'POST' }),
  deleteSubscription: (id) => apiFetch(`/subscriptions/${id}`, { method: 'DELETE' }),

  getSettings: () => apiFetch('/settings'),
  saveSettings: (payload) => apiFetch('/settings', { method: 'PUT', body: payload }),
  setPublicHost: (public_host) => apiFetch('/settings/public-host', { method: 'POST', body: { public_host } }),
  changePassword: (payload) => apiFetch('/settings/password', { method: 'POST', body: payload }),
  backupDbUrl: () => `${getApiBase()}/settings/backup-db`,
  restoreDb: (file) => {
    const fd = new FormData();
    fd.append('file', file);
    return apiFetch('/settings/restore-db', { method: 'POST', body: fd });
  },
  listBackups: () => apiFetch('/settings/backups'),
  backupNow: (send_telegram = false) =>
    apiFetch('/settings/backup-now', { method: 'POST', body: { send_telegram } }),
  backupTgTest: (payload = {}) =>
    apiFetch('/settings/backup-tg-test', { method: 'POST', body: payload }),
  downloadLocalBackupUrl: (filename) =>
    `${getApiBase()}/settings/backups/${encodeURIComponent(filename)}`,
  restoreLocalBackup: (filename) =>
    apiFetch(`/settings/backups/${encodeURIComponent(filename)}/restore`, { method: 'POST' }),
  deleteLocalBackup: (filename) =>
    apiFetch(`/settings/backups/${encodeURIComponent(filename)}`, { method: 'DELETE' }),

  restartPanel: () => apiFetch('/panel/restart', { method: 'POST' }),
  checkUpdates: (force = false) => apiFetch(`/system/updates${force ? '?force=1' : ''}`),
  upgradePanel: () => apiFetch('/system/upgrade-panel', { method: 'POST' }),
  upgradeShoes: () => apiFetch('/system/upgrade-shoes', { method: 'POST' }),
};
