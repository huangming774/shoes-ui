<template>
  <div>
    <a-alert
      type="info"
      show-icon
      :message="t('certs.guideTitle')"
      :description="t('certs.guideDesc')"
      style="margin-bottom: 14px"
    />

    <a-card size="small" style="margin-bottom: 14px">
      <a-space wrap>
        <a-button type="primary" @click="openMode('acme')">+ {{ t('certs.addAcme') }}</a-button>
        <a-button type="primary" ghost @click="openMode('acme_ip')">🌐 {{ t('certs.addIpAcme') }}</a-button>
        <a-button @click="openMode('selfsigned')">⚡ {{ t('certs.genSelfSigned') }}</a-button>
        <a-button @click="openMode('upload')">📋 {{ t('certs.uploadPem') }}</a-button>
        <a-button @click="openMode('files')">📁 {{ t('certs.addFileRef') }}</a-button>
        <a-button @click="loadCerts">↻ {{ t('app.refresh') }}</a-button>
      </a-space>
    </a-card>

    <a-card size="small" :body-style="{ padding: 0 }">
      <a-table
        :data-source="certs"
        :columns="columns"
        row-key="id"
        :loading="loading"
        :pagination="false"
        :scroll="{ x: 960 }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'name'">
            <code style="font-weight: 600">{{ record.name }}</code>
            <div v-if="record.remark" style="font-size: 11px; opacity: 0.7; margin-top: 2px">
              {{ record.remark }}
            </div>
          </template>

          <template v-else-if="column.key === 'cert_type'">
            <a-tag v-if="record.cert_type === 'acme'" color="green">ACME 域名</a-tag>
            <a-tag v-else-if="record.cert_type === 'acme_ip'" color="cyan">IP ACME</a-tag>
            <a-tag v-else color="blue">FILES</a-tag>
          </template>

          <template v-else-if="column.key === 'status'">
            <div style="font-size: 12px">
              <a-tag :color="statusColor(record.runtime?.status)">
                {{ statusLabel(record.runtime?.status) }}
              </a-tag>
              <span v-if="record.runtime?.status === 'issued' && record.runtime?.hours_left != null" style="margin-left: 4px">
                <template v-if="record.runtime.days_left >= 2">
                  {{ t('certs.daysLeft', { days: record.runtime.days_left }) }}
                </template>
                <template v-else>
                  {{ t('certs.hoursLeft', { hours: Math.max(0, record.runtime.hours_left) }) }}
                </template>
              </span>
              <div v-if="record.runtime?.issuer" style="font-size: 11px; opacity: 0.75; margin-top: 2px">
                CA: {{ record.runtime.issuer }}
                <a-tag v-if="record.runtime.is_self_signed" size="small" style="margin-left: 4px">Self-Signed</a-tag>
              </div>
              <div v-else-if="record.runtime?.message" style="font-size: 11px; opacity: 0.72; margin-top: 2px">
                {{ record.runtime.message }}
              </div>
            </div>
          </template>

          <template v-else-if="column.key === 'detail'">
            <div v-if="record.cert_type === 'acme'" style="font-size: 12px">
              <div><b>Domains:</b> {{ (record.domains || []).join(', ') }}</div>
              <div style="opacity: 0.72">
                {{ record.challenge_type === 'tls_alpn01' ? 'TLS-ALPN-01 (TCP 443)' : `HTTP-01 (${record.http01_listen || '0.0.0.0:80'})` }}
                <template v-if="record.email"> · {{ record.email }}</template>
              </div>
            </div>
            <div v-else-if="record.cert_type === 'acme_ip'" style="font-size: 12px">
              <div><b>IP SANs:</b> {{ ((record.runtime?.sans?.length ? record.runtime.sans : record.domains) || []).join(', ') }}</div>
              <div style="opacity: 0.72">
                HTTP-01 ({{ record.http01_listen || '0.0.0.0:80' }}) · 6d shortlived auto-renew
              </div>
              <div style="opacity: 0.65; font-size: 11px"><code>{{ record.cert_file }}</code></div>
            </div>
            <div v-else style="font-size: 12px">
              <div v-if="record.runtime?.sans?.length">
                <b>SANs:</b> {{ record.runtime.sans.join(', ') }}
              </div>
              <div><code>{{ record.cert_file }}</code></div>
              <div style="opacity: 0.7"><code>{{ record.key_file }}</code></div>
            </div>
          </template>

          <template v-else-if="column.key === 'usage'">
            <a-space wrap size="small">
              <a-tag v-if="record.runtime?.is_panel_https" color="purple">
                🔒 {{ t('certs.panelHttpsBadge') }}
              </a-tag>
              <a-tag v-for="ib in record.runtime?.used_by || []" :key="ib" color="geekblue">
                {{ ib }}
              </a-tag>
              <span
                v-if="!record.runtime?.is_panel_https && !(record.runtime?.used_by?.length)"
                style="opacity: 0.55; font-size: 12px"
              >
                {{ t('certs.unused') }}
              </span>
            </a-space>
          </template>

          <template v-else-if="column.key === 'actions'">
            <a-space wrap size="small">
              <a-button
                v-if="record.cert_type === 'acme_ip'"
                size="small"
                :loading="renewingId === record.id"
                @click="handleRenew(record)"
              >
                {{ t('certs.renewNow') }}
              </a-button>
              <a-button
                v-if="record.runtime?.status === 'issued'"
                size="small"
                :loading="applyingHttpsId === record.id"
                @click="handleApplyPanelHttps(record)"
              >
                🔒 {{ t('certs.applyPanelHttps') }}
              </a-button>
              <a-button
                v-if="record.cert_type === 'acme' || record.cert_file"
                size="small"
                @click="openEdit(record)"
              >
                {{ t('app.edit') }}
              </a-button>
              <a-popconfirm :title="t('app.deleteConfirm')" @confirm="handleDelete(record)">
                <a-button size="small" danger>{{ t('app.delete') }}</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- Certificate Modal -->
    <a-modal
      v-model:open="modalOpen"
      :title="modalTitle"
      width="680px"
      :confirm-loading="saving"
      @ok="handleSave"
    >
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('certs.sourceName')" required>
              <a-input v-model:value="form.name" placeholder="main-cert" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('app.remark')">
              <a-input v-model:value="form.remark" />
            </a-form-item>
          </a-col>
        </a-row>

        <template v-if="mode === 'selfsigned'">
          <a-alert type="info" show-icon :message="t('certs.selfSignedTip')" style="margin-bottom: 12px" />
          <a-form-item :label="t('certs.domains')" required>
            <a-input v-model:value="domainsStr" placeholder="203.0.113.10, localhost, 127.0.0.1" />
          </a-form-item>
        </template>

        <template v-else-if="mode === 'upload'">
          <a-form-item :label="t('certs.certPem')" required>
            <a-textarea
              v-model:value="uploadForm.cert_pem"
              :rows="5"
              style="font-family: monospace; font-size: 12px"
              placeholder="-----BEGIN CERTIFICATE-----..."
            />
          </a-form-item>
          <a-form-item :label="t('certs.keyPem')" required>
            <a-textarea
              v-model:value="uploadForm.key_pem"
              :rows="5"
              style="font-family: monospace; font-size: 12px"
              placeholder="-----BEGIN PRIVATE KEY-----..."
            />
          </a-form-item>
        </template>

        <template v-else-if="mode === 'acme_ip'">
          <a-alert type="info" show-icon :message="t('certs.ipAcmeTip')" style="margin-bottom: 12px" />
          <a-form-item :label="t('certs.ipTargets')" required>
            <a-input v-model:value="domainsStr" placeholder="203.0.113.10" />
          </a-form-item>
          <a-row :gutter="12">
            <a-col :span="12">
              <a-form-item :label="t('certs.email')">
                <a-input v-model:value="form.email" placeholder="admin@example.com (optional)" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item :label="t('certs.http01Listen')">
                <a-input v-model:value="form.http01_listen" placeholder="0.0.0.0:80" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-form-item :label="t('certs.acmeDir')">
            <a-select v-model:value="form.directory_url" @change="refreshAcmeMeta">
              <a-select-option value="https://acme-v02.api.letsencrypt.org/directory">
                Let's Encrypt Production (shortlived 6-day IP SSL)
              </a-select-option>
              <a-select-option value="https://acme-staging-v02.api.letsencrypt.org/directory">
                Let's Encrypt Staging (Testing)
              </a-select-option>
            </a-select>
          </a-form-item>
        </template>

        <template v-else-if="mode === 'acme'">
          <a-alert
            type="info"
            show-icon
            :message="form.challenge_type === 'tls_alpn01' ? t('certs.alpnTip') : t('certs.http01Tip')"
            style="margin-bottom: 12px"
          />
          <a-form-item :label="t('certs.acmeDomains')" required>
            <a-input v-model:value="domainsStr" placeholder="proxy.example.com" />
          </a-form-item>
          <a-row :gutter="12">
            <a-col :span="12">
              <a-form-item :label="t('certs.email')" required>
                <a-input v-model:value="form.email" placeholder="admin@example.com" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item :label="t('certs.challenge')">
                <a-select v-model:value="form.challenge_type">
                  <a-select-option value="http01">HTTP-01 (TCP 80)</a-select-option>
                  <a-select-option value="tls_alpn01">TLS-ALPN-01 (TCP 443)</a-select-option>
                </a-select>
              </a-form-item>
            </a-col>
          </a-row>
          <a-form-item v-if="form.challenge_type === 'http01'" :label="t('certs.http01Listen')">
            <a-input v-model:value="form.http01_listen" placeholder="0.0.0.0:80" />
          </a-form-item>
          <a-form-item :label="t('certs.acmeDir')">
            <a-select v-model:value="form.directory_url" @change="refreshAcmeMeta">
              <a-select-option value="https://acme-v02.api.letsencrypt.org/directory">
                Let's Encrypt Production
              </a-select-option>
              <a-select-option value="https://acme-staging-v02.api.letsencrypt.org/directory">
                Let's Encrypt Staging (Testing)
              </a-select-option>
            </a-select>
          </a-form-item>
          <a-form-item :label="t('certs.acmeTos')">
            <a-input
              v-model:value="form.terms_of_service"
              :placeholder="loadingMeta ? 'Fetching live Terms of Service...' : ''"
            />
          </a-form-item>
        </template>

        <template v-else>
          <a-form-item :label="t('inbounds.certFile')" required>
            <a-input v-model:value="form.cert_file" placeholder="/etc/letsencrypt/live/domain/fullchain.pem" />
          </a-form-item>
          <a-form-item :label="t('inbounds.keyFile')" required>
            <a-input v-model:value="form.key_file" placeholder="/etc/letsencrypt/live/domain/privkey.pem" />
          </a-form-item>
        </template>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { message, Modal } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';

const { t } = useI18n();
const loading = ref(false);
const saving = ref(false);
const loadingMeta = ref(false);
const renewingId = ref(null);
const applyingHttpsId = ref(null);
const certs = ref([]);
const detectedHost = ref('');
const detectedPublicIp = ref('');

const modalOpen = ref(false);
const mode = ref('acme');
const domainsStr = ref('');
const uploadForm = reactive({ cert_pem: '', key_pem: '' });

const DEFAULT_LE_DIR = 'https://acme-v02.api.letsencrypt.org/directory';
const DEFAULT_LE_TOS = 'https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf';

const form = reactive({
  id: 0,
  name: '',
  cert_type: 'files',
  cert_file: '',
  key_file: '',
  domains: [],
  email: '',
  directory_url: DEFAULT_LE_DIR,
  terms_of_service: DEFAULT_LE_TOS,
  challenge_type: 'http01',
  http01_listen: '0.0.0.0:80',
  remark: '',
});

const modalTitle = computed(() => {
  if (mode.value === 'acme') return t('certs.addAcme');
  if (mode.value === 'acme_ip') return t('certs.addIpAcme');
  if (mode.value === 'selfsigned') return t('certs.genSelfSigned');
  if (mode.value === 'upload') return t('certs.uploadPem');
  return t('certs.addFileRef');
});

const columns = computed(() => [
  { title: t('certs.sourceName'), key: 'name', width: 155 },
  { title: t('certs.type'), key: 'cert_type', width: 105 },
  { title: t('certs.status'), key: 'status', width: 190 },
  { title: 'Details / Paths', key: 'detail' },
  { title: t('certs.usage'), key: 'usage', width: 170 },
  { title: t('app.actions'), key: 'actions', width: 240 },
]);

function statusColor(st) {
  if (st === 'issued') return 'green';
  if (st === 'pending') return 'processing';
  if (st === 'unreferenced_alpn') return 'gold';
  if (st === 'expired' || st === 'missing' || st === 'invalid') return 'red';
  return 'default';
}

function statusLabel(st) {
  if (st === 'issued') return t('certs.statusIssued');
  if (st === 'pending') return t('certs.statusPending');
  if (st === 'unreferenced_alpn') return t('certs.statusUnrefAlpn');
  if (st === 'expired') return t('certs.statusExpired');
  if (st === 'missing') return t('certs.statusMissing');
  if (st === 'invalid') return t('certs.statusInvalid');
  return st || '-';
}

function looksLikeIp(val) {
  if (!val) return false;
  const s = val.trim().replace(/^\[|\]$/g, '');
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || s.includes(':');
}

async function loadCerts() {
  loading.value = true;
  try {
    const [list, settingsRes] = await Promise.all([
      api.listCerts(),
      api.getSettings().catch(() => null),
    ]);
    certs.value = list;
    if (settingsRes) {
      detectedPublicIp.value = settingsRes.detected_public_ip || '';
      detectedHost.value =
        settingsRes.settings?.public_host ||
        settingsRes.effective_share_host ||
        settingsRes.detected_public_ip ||
        '';
    }
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

onMounted(loadCerts);

async function refreshAcmeMeta() {
  if (!form.directory_url) return;
  loadingMeta.value = true;
  try {
    const meta = await api.acmeMeta(form.directory_url);
    form.terms_of_service = meta.terms_of_service || '';
  } catch {
    // Keep current fallback if offline
  } finally {
    loadingMeta.value = false;
  }
}

function openMode(m) {
  mode.value = m;
  const suffix = Date.now().toString().slice(-4);
  Object.assign(form, {
    id: 0,
    name:
      m === 'selfsigned'
        ? `self-${suffix}`
        : m === 'acme_ip'
          ? `ip-ssl-${suffix}`
          : m === 'acme'
            ? 'domain-acme'
            : `cert-${suffix}`,
    cert_type: m === 'acme' ? 'acme' : m === 'acme_ip' ? 'acme_ip' : 'files',
    cert_file: '',
    key_file: '',
    domains: [],
    email: '',
    directory_url: DEFAULT_LE_DIR,
    terms_of_service: DEFAULT_LE_TOS,
    challenge_type: 'http01',
    http01_listen: '0.0.0.0:80',
    remark: '',
  });
  if (m === 'selfsigned') {
    const parts = [];
    if (detectedHost.value && detectedHost.value !== '127.0.0.1' && detectedHost.value !== 'localhost') {
      parts.push(detectedHost.value);
    }
    if (detectedPublicIp.value && !parts.includes(detectedPublicIp.value)) {
      parts.push(detectedPublicIp.value);
    }
    parts.push('localhost', '127.0.0.1');
    domainsStr.value = parts.join(', ');
  } else if (m === 'acme_ip') {
    domainsStr.value =
      detectedPublicIp.value || (looksLikeIp(detectedHost.value) ? detectedHost.value : '');
  } else if (m === 'acme') {
    domainsStr.value =
      detectedHost.value && !looksLikeIp(detectedHost.value) && detectedHost.value !== 'localhost'
        ? detectedHost.value
        : '';
  } else {
    domainsStr.value = '';
  }
  uploadForm.cert_pem = '';
  uploadForm.key_pem = '';
  modalOpen.value = true;
  if (m === 'acme' || m === 'acme_ip') {
    refreshAcmeMeta();
  }
}

function openEdit(rec) {
  mode.value =
    rec.cert_type === 'acme' ? 'acme' : rec.cert_type === 'acme_ip' ? 'acme_ip' : 'files';
  Object.assign(form, JSON.parse(JSON.stringify(rec)));
  delete form.runtime;
  domainsStr.value = (rec.domains || []).join(', ');
  modalOpen.value = true;
  if (mode.value === 'acme') {
    refreshAcmeMeta();
  }
}

async function handleSave() {
  saving.value = true;
  try {
    const items = domainsStr.value
      .split(/[\s,;]+/)
      .map((d) => d.trim())
      .filter(Boolean);

    if (mode.value === 'selfsigned') {
      await api.selfSignedCert({ name: form.name, domains: items, remark: form.remark });
    } else if (mode.value === 'upload') {
      await api.uploadCert({
        id: form.id,
        name: form.name,
        cert_pem: uploadForm.cert_pem,
        key_pem: uploadForm.key_pem,
        remark: form.remark,
      });
    } else if (mode.value === 'acme_ip') {
      await api.issueIpCert({
        id: form.id,
        name: form.name,
        ips: items,
        email: form.email,
        directory_url: form.directory_url,
        http01_listen: form.http01_listen,
        remark: form.remark,
      });
    } else {
      await api.saveCert({ ...form, domains: items });
    }
    message.success(t('app.saveSuccess'));
    modalOpen.value = false;
    await loadCerts();
  } catch (e) {
    message.error(e.message);
  } finally {
    saving.value = false;
  }
}

async function handleRenew(rec) {
  renewingId.value = rec.id;
  try {
    await api.renewCert(rec.id);
    message.success(t('app.saveSuccess'));
    await loadCerts();
  } catch (e) {
    message.error(e.message);
  } finally {
    renewingId.value = null;
  }
}

async function handleApplyPanelHttps(rec) {
  applyingHttpsId.value = rec.id;
  try {
    const res = await api.applyPanelHttps(rec.id);
    if (res.hot_reloaded) {
      message.success(t('certs.panelHttpsAppliedHot'));
    } else {
      Modal.confirm({
        title: t('certs.applyPanelHttps'),
        content: t('certs.panelHttpsAppliedRestart'),
        okText: t('settings.restartPanel'),
        onOk: async () => {
          const r = await api.restartPanel();
          const scheme = r?.target_scheme || 'https';
          const port = r?.target_port || window.location.port;
          const bp = r?.target_base_path || window.__SHOES_BASE__ || '/';
          const suffix = bp === '/' ? '/' : `${bp.replace(/\/+$/, '')}/`;
          const host = window.location.hostname;
          const hostFmt = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
          message.loading(t('settings.restartingPanel'), 4);
          setTimeout(() => {
            window.location.href = `${scheme}://${hostFmt}:${port}${suffix}`;
          }, 3500);
        },
      });
    }
    await loadCerts();
  } catch (e) {
    message.error(e.message);
  } finally {
    applyingHttpsId.value = null;
  }
}

async function handleDelete(rec) {
  try {
    await api.deleteCert(rec.id);
    message.success('Deleted');
    await loadCerts();
  } catch (e) {
    message.error(e.message);
  }
}
</script>
