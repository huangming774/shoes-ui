<template>
  <div class="cluster-view">
    <!-- Top 4 KPI Summary Cards -->
    <a-row :gutter="[14, 14]" style="margin-bottom: 14px">
      <a-col :xs="24" :sm="12" :xl="6">
        <a-card size="small" class="cluster-kpi-card">
          <div class="cluster-kpi-label">{{ t('cluster.onlineNodes') }}</div>
          <div class="cluster-kpi-value">
            <span class="cluster-kpi-accent">{{ summary.nodes_online }}</span>
            <span class="cluster-kpi-muted"> / {{ summary.nodes_total }}</span>
          </div>
          <div class="cluster-kpi-sub">
            {{ t('cluster.shoesRunning') }}: <strong>{{ summary.shoes_running }}</strong> / {{ summary.nodes_total }}
          </div>
        </a-card>
      </a-col>

      <a-col :xs="24" :sm="12" :xl="6">
        <a-card size="small" class="cluster-kpi-card">
          <div class="cluster-kpi-label">{{ t('cluster.proxyNodes') }}</div>
          <div class="cluster-kpi-value">
            <span class="cluster-kpi-accent">{{ summary.inbounds_enabled }}</span>
            <span class="cluster-kpi-muted"> / {{ summary.inbounds_total }}</span>
          </div>
          <div class="cluster-kpi-sub">
            {{ t('cluster.clientsTotal') }}: <strong>{{ summary.clients_total }}</strong>
            <span v-if="regionBadges.length" class="cluster-region-tags">
              <a-tag v-for="item in regionBadges" :key="item.label" color="blue" style="margin: 0">
                {{ item.label }} ×{{ item.count }}
              </a-tag>
            </span>
          </div>
        </a-card>
      </a-col>

      <a-col :xs="24" :sm="12" :xl="6">
        <a-card size="small" class="cluster-kpi-card">
          <div class="cluster-kpi-label">{{ t('cluster.liveSpeed') }}</div>
          <div class="cluster-kpi-value cluster-kpi-speed">
            <span>↑ {{ formatSpeed(summaryUpSpeed) }}</span>
            <span>↓ {{ formatSpeed(summaryDownSpeed) }}</span>
          </div>
          <div class="cluster-kpi-sub">
            {{ t('cluster.activeConns') }}: <strong>{{ summary.active_connections }}</strong>
          </div>
        </a-card>
      </a-col>

      <a-col :xs="24" :sm="12" :xl="6">
        <a-card size="small" class="cluster-kpi-card">
          <div class="cluster-kpi-label">{{ t('cluster.totalTraffic') }}</div>
          <div class="cluster-kpi-value">
            {{ formatBytes((summary.total_up_bytes || 0) + (summary.total_down_bytes || 0)) }}
          </div>
          <div class="cluster-kpi-sub">
            ↑ {{ formatBytes(summary.total_up_bytes) }} · ↓ {{ formatBytes(summary.total_down_bytes) }}
          </div>
        </a-card>
      </a-col>
    </a-row>

    <!-- Cluster Nodes Overview Table -->
    <a-card size="small" style="margin-bottom: 14px" :body-style="{ padding: 0 }">
      <template #title>
        <span>🌐 {{ t('cluster.nodesTitle') }}</span>
      </template>
      <template #extra>
        <a-space wrap :size="8">
          <a-button type="primary" size="small" @click="openAddModal">
            + {{ t('cluster.addNode') }}
          </a-button>
          <a-button size="small" :loading="syncingAll" @click="handleSyncAll">
            ↻ {{ t('cluster.syncAll') }}
          </a-button>
          <a-button size="small" @click="emit('navigate', 'subscriptions')">
            🔗 {{ t('cluster.goSubscriptions') }}
          </a-button>
        </a-space>
      </template>

      <a-table
        :data-source="tableRows"
        :columns="columns"
        row-key="rowKey"
        :loading="loading && !loadedOnce"
        :pagination="false"
        :scroll="{ x: 1080 }"
        size="middle"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'node'">
            <div class="cluster-node-cell">
              <div class="cluster-node-title">
                <span v-if="record.regionFlag" class="cluster-flag">{{ record.regionFlag }}</span>
                <strong>{{ record.name }}</strong>
                <a-tag v-if="record.isLocal" color="blue" style="margin: 0">
                  {{ t('cluster.localBadge') }}
                </a-tag>
                <a-tag v-else-if="!record.enable" color="default" style="margin: 0">
                  {{ t('cluster.disabledBadge') }}
                </a-tag>
                <a-tag v-if="record.region" color="cyan" style="margin: 0">
                  {{ record.region }}
                </a-tag>
              </div>
              <div class="cluster-node-meta">
                <code v-if="record.shareHost">{{ record.shareHost }}</code>
                <template v-if="!record.isLocal && record.apiUrl">
                  <span v-if="record.shareHost"> · </span>
                  <a :href="record.apiUrl" target="_blank" rel="noopener noreferrer">
                    {{ record.apiUrl }}
                  </a>
                </template>
                <template v-if="record.remark">
                  <span> · {{ record.remark }}</span>
                </template>
              </div>
            </div>
          </template>

          <template v-else-if="column.key === 'status'">
            <template v-if="record.isLocal">
              <a-badge status="success" :text="t('cluster.online')" />
              <div class="cluster-sub-line">v{{ record.panelVersion }}</div>
            </template>
            <template v-else-if="!record.enable">
              <a-badge status="default" :text="t('cluster.disabledBadge')" />
            </template>
            <template v-else-if="record.online">
              <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap">
                <a-badge status="success" :text="t('cluster.online')" />
                <a-tag v-if="record.latencyMs != null" color="green" style="margin: 0">
                  {{ record.latencyMs }} ms
                </a-tag>
              </div>
              <div class="cluster-sub-line">v{{ record.panelVersion || '—' }}</div>
            </template>
            <template v-else>
              <a-tooltip :title="record.lastError || t('cluster.pendingSync')">
                <a-badge
                  :status="record.lastError ? 'error' : 'processing'"
                  :text="record.lastError ? t('cluster.offline') : t('cluster.pendingSync')"
                />
              </a-tooltip>
              <div v-if="record.lastError" class="cluster-err-line">{{ record.lastError }}</div>
            </template>
          </template>

          <template v-else-if="column.key === 'shoes'">
            <template v-if="record.hasTelemetry">
              <a-tag :color="record.shoes?.running ? 'success' : 'error'" style="margin: 0">
                {{ record.shoes?.running ? t('dashboard.running') : t('dashboard.stopped') }}
              </a-tag>
              <div class="cluster-sub-line">{{ record.shoes?.version || '—' }}</div>
            </template>
            <span v-else class="cluster-sub-line">—</span>
          </template>

          <template v-else-if="column.key === 'resources'">
            <template v-if="record.hasTelemetry">
              <div>CPU {{ Math.round(record.system?.cpu_usage || 0) }}%</div>
              <div class="cluster-sub-line">
                RAM {{ memPercent(record.system) }}%
                <span v-if="record.system?.mem_total">
                  ({{ formatBytes(record.system.mem_used, 1) }}/{{ formatBytes(record.system.mem_total, 1) }})
                </span>
              </div>
            </template>
            <span v-else class="cluster-sub-line">—</span>
          </template>

          <template v-else-if="column.key === 'speed'">
            <template v-if="record.hasTelemetry">
              <div style="white-space: nowrap">
                ↑ {{ formatSpeed(rowUpSpeed(record.system)) }} · ↓ {{ formatSpeed(rowDownSpeed(record.system)) }}
              </div>
              <div class="cluster-sub-line">
                {{ t('cluster.activeConns') }}: {{ record.system?.active_connections || 0 }}
                <span v-if="!record.system?.clash_online" :title="t('cluster.nicFallbackHint')"> (NIC)</span>
              </div>
            </template>
            <span v-else class="cluster-sub-line">—</span>
          </template>

          <template v-else-if="column.key === 'traffic'">
            <template v-if="record.hasTelemetry">
              <div style="white-space: nowrap">↑ {{ formatBytes(record.totals?.up_bytes) }}</div>
              <div class="cluster-sub-line" style="white-space: nowrap">
                ↓ {{ formatBytes(record.totals?.down_bytes) }}
              </div>
            </template>
            <span v-else class="cluster-sub-line">—</span>
          </template>

          <template v-else-if="column.key === 'inbounds'">
            <template v-if="record.hasTelemetry">
              <div>
                <strong>{{ record.totals?.inbounds_enabled || 0 }}</strong> / {{ record.totals?.inbounds_total || 0 }}
                <span class="cluster-sub-line">({{ record.totals?.clients_total || 0 }})</span>
              </div>
            </template>
            <div v-if="!record.isLocal" style="margin-top: 2px">
              <a-tag :color="record.includeInSub ? 'purple' : 'default'" style="margin: 0">
                {{ record.includeInSub ? t('cluster.subIncluded') : t('cluster.subExcluded') }}
              </a-tag>
            </div>
          </template>

          <template v-else-if="column.key === 'actions'">
            <template v-if="record.isLocal">
              <a-button size="small" @click="scrollToLocalCard">{{ t('app.edit') }}</a-button>
            </template>
            <a-space v-else :size="6">
              <a-button
                size="small"
                :loading="syncingId === record.id"
                :disabled="!record.enable"
                @click="handleSyncOne(record.id)"
              >
                ↻
              </a-button>
              <a-button size="small" @click="openEditModal(record.raw)">{{ t('app.edit') }}</a-button>
              <a-popconfirm :title="t('cluster.deleteConfirm')" @confirm="handleDeleteNode(record.id)">
                <a-button size="small" danger>{{ t('app.delete') }}</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>

      <div v-if="remoteNodes.length === 0" class="cluster-empty-hint">
        💡 {{ t('cluster.emptyRemoteHint') }}
      </div>
    </a-card>

    <!-- Local Node Identity & Read-Only Federation Token Card -->
    <a-card ref="localCardRef" size="small" :title="`🏷️ ${t('cluster.localCardTitle')}`">
      <a-row :gutter="[20, 16]">
        <a-col :xs="24" :lg="11">
          <div class="cluster-section-title">{{ t('cluster.localIdentityTitle') }}</div>
          <a-form layout="vertical">
            <a-form-item :label="t('cluster.localName')">
              <a-input
                v-model:value="localForm.local_name"
                :placeholder="t('cluster.localNamePlaceholder')"
                @input="localFormDirty = true"
              />
            </a-form-item>
            <a-row :gutter="10">
              <a-col :xs="24" :sm="10">
                <a-form-item :label="t('cluster.regionPreset')">
                  <a-select
                    :value="matchPresetCode(localForm.local_region)"
                    allow-clear
                    :placeholder="t('cluster.regionPreset')"
                    @change="onLocalPresetChange"
                  >
                    <a-select-option v-for="p in REGION_PRESETS" :key="p.code" :value="p.code">
                      {{ p.flag }} {{ p.code }} · {{ p.label }}
                    </a-select-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :xs="16" :sm="9">
                <a-form-item :label="t('cluster.regionLabel')">
                  <a-input
                    v-model:value="localForm.local_region"
                    :placeholder="t('cluster.regionCustomPlaceholder')"
                    @input="localFormDirty = true"
                  />
                </a-form-item>
              </a-col>
              <a-col :xs="8" :sm="5">
                <a-form-item :label="t('cluster.regionFlag')">
                  <a-input
                    v-model:value="localForm.local_region_flag"
                    placeholder="🇺🇸"
                    @input="localFormDirty = true"
                  />
                </a-form-item>
              </a-col>
            </a-row>
            <a-button type="primary" :loading="savingLocal" @click="handleSaveLocal">
              💾 {{ t('cluster.saveIdentity') }}
            </a-button>
          </a-form>
        </a-col>

        <a-col :xs="24" :lg="13">
          <div class="cluster-section-title" style="display: flex; align-items: center; gap: 8px">
            <span>🔑 {{ t('cluster.tokenTitle') }}</span>
            <a-tag :color="localInfo.api_token_enabled ? 'green' : 'default'" style="margin: 0">
              {{ localInfo.api_token_enabled ? t('cluster.tokenEnabled') : t('cluster.tokenDisabled') }}
            </a-tag>
          </div>
          <a-alert
            type="info"
            show-icon
            :message="t('cluster.tokenTip')"
            style="margin-bottom: 12px; font-size: 12px"
          />
          <div style="display: flex; gap: 8px; margin-bottom: 12px; align-items: center">
            <a-input
              :value="displayedLocalToken"
              readonly
              style="font-family: monospace"
              :placeholder="t('cluster.tokenDisabled')"
            />
            <a-button
              v-if="localInfo.api_token_enabled"
              @click="showLocalToken = !showLocalToken"
            >
              {{ showLocalToken ? '🙈' : '👁️' }}
            </a-button>
            <a-button
              v-if="localInfo.api_token_enabled"
              @click="copyLocalToken"
            >
              {{ t('cluster.copyToken') }}
            </a-button>
          </div>
          <a-space wrap :size="8">
            <a-popconfirm
              v-if="localInfo.api_token_enabled"
              :title="t('cluster.rotateTokenConfirm')"
              @confirm="handleRotateToken"
            >
              <a-button :loading="rotatingToken">🔄 {{ t('cluster.rotateToken') }}</a-button>
            </a-popconfirm>
            <a-button v-else type="primary" :loading="rotatingToken" @click="handleRotateToken">
              🔑 {{ t('cluster.generateToken') }}
            </a-button>

            <a-button
              type="primary"
              ghost
              :disabled="!localInfo.api_token_enabled"
              @click="copyPairingCode"
            >
              📋 {{ t('cluster.copyPairingCode') }}
            </a-button>

            <a-popconfirm
              v-if="localInfo.api_token_enabled"
              :title="t('cluster.revokeTokenConfirm')"
              @confirm="handleRevokeToken"
            >
              <a-button danger :loading="revokingToken">{{ t('cluster.revokeToken') }}</a-button>
            </a-popconfirm>
          </a-space>
        </a-col>
      </a-row>
    </a-card>

    <!-- Mount / Edit Remote Node Modal -->
    <a-modal
      v-model:open="nodeModalOpen"
      :title="nodeForm.id ? t('cluster.modalEditTitle') : t('cluster.modalAddTitle')"
      width="640px"
      :confirm-loading="savingNode"
      @ok="handleSaveNode"
    >
      <a-form layout="vertical">
        <!-- Quick Pairing Code Paste -->
        <a-form-item :label="t('cluster.pairingPasteLabel')">
          <div style="display: flex; gap: 8px">
            <a-input
              v-model:value="pairingInput"
              :placeholder="t('cluster.pairingPastePlaceholder')"
              @paste="onPairingPaste"
            />
            <a-button @click="applyPairingCode(pairingInput)">
              {{ t('cluster.pairingParseBtn') }}
            </a-button>
          </div>
        </a-form-item>

        <a-form-item :label="t('cluster.apiUrl')" required>
          <a-input
            v-model:value="nodeForm.api_url"
            :placeholder="t('cluster.apiUrlPlaceholder')"
          />
        </a-form-item>

        <a-form-item
          :label="t('cluster.apiToken')"
          :required="!nodeForm.id"
          :extra="nodeForm.id && editingTokenPreview ? `${t('cluster.apiTokenKeepHint')} (${editingTokenPreview})` : ''"
        >
          <a-input-password
            v-model:value="nodeForm.api_token"
            :placeholder="nodeForm.id ? t('cluster.apiTokenKeepHint') : t('cluster.apiTokenPlaceholder')"
          />
        </a-form-item>

        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 14px">
          <a-checkbox v-model:checked="nodeForm.allow_insecure">
            {{ t('cluster.allowInsecure') }}
          </a-checkbox>
          <a-button type="dashed" :loading="testingNode" @click="handleTestNode">
            ⚡ {{ t('cluster.testConnection') }}
          </a-button>
        </div>

        <a-alert
          v-if="testResult"
          type="success"
          show-icon
          style="margin-bottom: 14px"
          :message="`${t('cluster.testSuccess')} · ${testResult.latency_ms} ms · v${testResult.panel_version}`"
          :description="`Host: ${testResult.share_host || '—'} · Shoes: ${testResult.shoes_running ? t('dashboard.running') : t('dashboard.stopped')} (${testResult.shoes_version || '—'}) · Nodes: ${testResult.inbounds_enabled}/${testResult.inbounds_total} (${testResult.clients_total})`"
        />
        <a-alert
          v-else-if="testError"
          type="error"
          show-icon
          style="margin-bottom: 14px"
          :message="testError"
        />

        <a-row :gutter="10">
          <a-col :xs="24" :sm="10">
            <a-form-item :label="t('cluster.nodeName')" required>
              <a-input v-model:value="nodeForm.name" placeholder="JP-Tokyo-01" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :sm="6">
            <a-form-item :label="t('cluster.regionPreset')">
              <a-select
                :value="matchPresetCode(nodeForm.region)"
                allow-clear
                :placeholder="t('cluster.regionPreset')"
                @change="onNodePresetChange"
              >
                <a-select-option v-for="p in REGION_PRESETS" :key="p.code" :value="p.code">
                  {{ p.flag }} {{ p.code }}
                </a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :xs="16" :sm="5">
            <a-form-item :label="t('cluster.regionLabel')">
              <a-input v-model:value="nodeForm.region" placeholder="JP" />
            </a-form-item>
          </a-col>
          <a-col :xs="8" :sm="3">
            <a-form-item :label="t('cluster.regionFlag')">
              <a-input v-model:value="nodeForm.region_flag" placeholder="🇯🇵" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="10">
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('cluster.nodePrefix')">
              <a-input
                v-model:value="nodeForm.node_prefix"
                :placeholder="t('cluster.nodePrefixPlaceholder')"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('cluster.shareHostOverride')">
              <a-input
                v-model:value="nodeForm.share_host_override"
                :placeholder="t('cluster.shareHostPlaceholder')"
              />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="10">
          <a-col :xs="12" :sm="8">
            <a-form-item :label="t('app.enable')">
              <a-switch v-model:checked="nodeForm.enable" />
            </a-form-item>
          </a-col>
          <a-col :xs="12" :sm="16">
            <a-form-item :label="t('cluster.includeInSub')">
              <a-switch v-model:checked="nodeForm.include_in_sub" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-form-item :label="t('cluster.remark')">
          <a-input v-model:value="nodeForm.remark" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { copyText, formatBytes, formatSpeed } from '../utils';

const emit = defineEmits(['navigate']);
const { t } = useI18n();

const REGION_PRESETS = [
  { code: 'HK', flag: '🇭🇰', label: 'Hong Kong' },
  { code: 'JP', flag: '🇯🇵', label: 'Japan' },
  { code: 'SG', flag: '🇸🇬', label: 'Singapore' },
  { code: 'TW', flag: '🇹🇼', label: 'Taiwan' },
  { code: 'US', flag: '🇺🇸', label: 'United States' },
  { code: 'KR', flag: '🇰🇷', label: 'Korea' },
  { code: 'UK', flag: '🇬🇧', label: 'United Kingdom' },
  { code: 'DE', flag: '🇩🇪', label: 'Germany' },
  { code: 'NL', flag: '🇳🇱', label: 'Netherlands' },
  { code: 'FR', flag: '🇫🇷', label: 'France' },
  { code: 'CA', flag: '🇨🇦', label: 'Canada' },
  { code: 'AU', flag: '🇦🇺', label: 'Australia' },
  { code: 'TR', flag: '🇹🇷', label: 'Turkey' },
  { code: 'IN', flag: '🇮🇳', label: 'India' },
  { code: 'RU', flag: '🇷🇺', label: 'Russia' },
];

const loading = ref(false);
const loadedOnce = ref(false);
const syncingAll = ref(false);
const syncingId = ref(0);
const savingLocal = ref(false);
const rotatingToken = ref(false);
const revokingToken = ref(false);
const showLocalToken = ref(false);
const localCardRef = ref(null);

const localInfo = ref({
  instance_id: '',
  local_name: 'Local Panel',
  local_region: '',
  local_region_flag: '',
  api_token: '',
  api_token_enabled: false,
  panel_version: '',
  share_host: '',
  panel_url: '',
  shoes: {},
  system: {},
  totals: {},
});

const localForm = reactive({
  local_name: '',
  local_region: '',
  local_region_flag: '',
});
let localFormDirty = false;

const remoteNodes = ref([]);
const summary = ref({
  nodes_total: 1,
  nodes_online: 1,
  shoes_running: 0,
  inbounds_total: 0,
  inbounds_enabled: 0,
  clients_total: 0,
  active_connections: 0,
  proxy_up_speed: 0,
  proxy_down_speed: 0,
  net_rx_speed: 0,
  net_tx_speed: 0,
  total_up_bytes: 0,
  total_down_bytes: 0,
  regions: {},
});

const nodeModalOpen = ref(false);
const savingNode = ref(false);
const testingNode = ref(false);
const testResult = ref(null);
const testError = ref('');
const pairingInput = ref('');
const editingTokenPreview = ref('');

const nodeForm = reactive({
  id: 0,
  name: '',
  region: '',
  region_flag: '',
  api_url: '',
  api_token: '',
  share_host_override: '',
  allow_insecure: false,
  enable: true,
  include_in_sub: true,
  node_prefix: '',
  remark: '',
  sort_order: 0,
});

const columns = computed(() => [
  { title: t('cluster.colNode'), key: 'node', width: 250 },
  { title: t('cluster.colStatus'), key: 'status', width: 155 },
  { title: t('cluster.colShoes'), key: 'shoes', width: 120 },
  { title: t('cluster.colResources'), key: 'resources', width: 150 },
  { title: t('cluster.colSpeed'), key: 'speed', width: 170 },
  { title: t('cluster.colTraffic'), key: 'traffic', width: 120 },
  { title: t('cluster.colInbounds'), key: 'inbounds', width: 125 },
  { title: t('app.actions'), key: 'actions', width: 155 },
]);

const regionBadges = computed(() => {
  const entries = Object.entries(summary.value.regions || {});
  return entries.map(([label, count]) => ({ label, count }));
});

const summaryUpSpeed = computed(() =>
  (summary.value.proxy_up_speed || 0) > 0
    ? summary.value.proxy_up_speed
    : summary.value.net_tx_speed || 0
);
const summaryDownSpeed = computed(() =>
  (summary.value.proxy_down_speed || 0) > 0
    ? summary.value.proxy_down_speed
    : summary.value.net_rx_speed || 0
);

const displayedLocalToken = computed(() => {
  const tok = localInfo.value.api_token || '';
  if (!tok) return '';
  if (showLocalToken.value) return tok;
  if (tok.length <= 12) return '••••••••••••';
  return `${tok.slice(0, 7)}••••••••••••••••${tok.slice(-4)}`;
});

const tableRows = computed(() => {
  const loc = localInfo.value;
  const rows = [
    {
      rowKey: 'local',
      isLocal: true,
      id: 0,
      name: loc.local_name || 'Local Panel',
      region: loc.local_region || '',
      regionFlag: loc.local_region_flag || '',
      shareHost: loc.share_host || '',
      apiUrl: loc.panel_url || '',
      remark: '',
      enable: true,
      includeInSub: true,
      online: true,
      latencyMs: 0,
      lastError: '',
      panelVersion: loc.panel_version || '',
      hasTelemetry: true,
      shoes: loc.shoes || {},
      system: loc.system || {},
      totals: loc.totals || {},
      raw: null,
    },
  ];

  for (const item of remoteNodes.value) {
    const n = item.node || {};
    const snap = item.snapshot || null;
    rows.push({
      rowKey: `remote-${n.id}`,
      isLocal: false,
      id: n.id,
      name: n.name || `Node #${n.id}`,
      region: n.region || '',
      regionFlag: n.region_flag || '',
      shareHost: n.share_host_override || snap?.share_host || '',
      apiUrl: n.api_url || '',
      remark: n.remark || '',
      enable: Boolean(n.enable),
      includeInSub: n.include_in_sub !== false,
      online: Boolean(snap?.online),
      latencyMs: snap?.latency_ms ?? null,
      lastError: snap?.last_error || '',
      panelVersion: snap?.panel_version || '',
      hasTelemetry: Boolean(snap && snap.last_ok_at > 0),
      shoes: snap?.shoes || {},
      system: snap?.system || {},
      totals: snap?.totals || {},
      raw: item,
    });
  }
  return rows;
});

function matchPresetCode(region) {
  const norm = (region || '').trim().toUpperCase();
  const found = REGION_PRESETS.find((p) => p.code === norm);
  return found ? found.code : undefined;
}

function onLocalPresetChange(code) {
  localFormDirty = true;
  if (!code) return;
  const found = REGION_PRESETS.find((p) => p.code === code);
  if (found) {
    localForm.local_region = found.code;
    localForm.local_region_flag = found.flag;
  }
}

function onNodePresetChange(code) {
  if (!code) return;
  const found = REGION_PRESETS.find((p) => p.code === code);
  if (found) {
    nodeForm.region = found.code;
    nodeForm.region_flag = found.flag;
  }
}

function memPercent(sys) {
  if (!sys?.mem_total) return 0;
  return Math.min(100, Math.round((sys.mem_used / sys.mem_total) * 100));
}

function rowUpSpeed(sys) {
  if (!sys) return 0;
  return sys.clash_online ? sys.proxy_up_speed || 0 : sys.net_tx_speed || 0;
}

function rowDownSpeed(sys) {
  if (!sys) return 0;
  return sys.clash_online ? sys.proxy_down_speed || 0 : sys.net_rx_speed || 0;
}

function applyOverviewData(data, syncLocalFields = false) {
  if (!data) return;
  localInfo.value = data.local || localInfo.value;
  remoteNodes.value = data.nodes || [];
  summary.value = data.summary || summary.value;
  if (syncLocalFields || !loadedOnce.value || !localFormDirty) {
    localForm.local_name = localInfo.value.local_name || '';
    localForm.local_region = localInfo.value.local_region || '';
    localForm.local_region_flag = localInfo.value.local_region_flag || '';
  }
  loadedOnce.value = true;
}

async function loadOverview(silent = false) {
  if (!silent) loading.value = true;
  try {
    const data = await api.clusterOverview();
    applyOverviewData(data, !silent);
  } catch (e) {
    if (!silent) message.error(e.message);
  } finally {
    if (!silent) loading.value = false;
  }
}

async function handleSyncAll() {
  syncingAll.value = true;
  try {
    const data = await api.clusterSyncAll();
    applyOverviewData(data, false);
    message.success(t('cluster.syncDone'));
  } catch (e) {
    message.error(e.message);
  } finally {
    syncingAll.value = false;
  }
}

async function handleSyncOne(id) {
  syncingId.value = id;
  try {
    await api.clusterSyncOne(id);
    await loadOverview(true);
    message.success(t('cluster.syncDone'));
  } catch (e) {
    message.error(e.message);
  } finally {
    syncingId.value = 0;
  }
}

async function handleSaveLocal() {
  savingLocal.value = true;
  try {
    await api.clusterSaveLocal({
      local_name: localForm.local_name,
      local_region: localForm.local_region,
      local_region_flag: localForm.local_region_flag,
    });
    localFormDirty = false;
    await loadOverview(true);
    message.success(t('cluster.identitySaved'));
  } catch (e) {
    message.error(e.message);
  } finally {
    savingLocal.value = false;
  }
}

async function handleRotateToken() {
  rotatingToken.value = true;
  try {
    await api.clusterRotateToken();
    showLocalToken.value = true;
    await loadOverview(true);
    message.success(t('cluster.tokenRotated'));
  } catch (e) {
    message.error(e.message);
  } finally {
    rotatingToken.value = false;
  }
}

async function handleRevokeToken() {
  revokingToken.value = true;
  try {
    await api.clusterRevokeToken();
    showLocalToken.value = false;
    await loadOverview(true);
    message.success(t('cluster.tokenRevoked'));
  } catch (e) {
    message.error(e.message);
  } finally {
    revokingToken.value = false;
  }
}

async function copyLocalToken() {
  if (!localInfo.value.api_token) return;
  await copyText(localInfo.value.api_token);
  message.success(t('app.copied'));
}

function effectiveLocalPanelUrl() {
  const bp = typeof window !== 'undefined' && window.__SHOES_BASE__ ? window.__SHOES_BASE__ : '/';
  const trimmedBp = bp.replace(/\/+$/, '');
  const browserOrigin = typeof window !== 'undefined' ? window.location.origin : '';
  const serverUrl = (localInfo.value.panel_url || '').replace(/\/+$/, '');
  const isBrowserLoopback = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(browserOrigin);
  if (browserOrigin && !isBrowserLoopback) {
    return `${browserOrigin}${trimmedBp}`;
  }
  return serverUrl || `${browserOrigin}${trimmedBp}`;
}

async function copyPairingCode() {
  if (!localInfo.value.api_token) return;
  const payload = {
    v: 1,
    name: localInfo.value.local_name || '',
    region: localInfo.value.local_region || '',
    region_flag: localInfo.value.local_region_flag || '',
    api_url: effectiveLocalPanelUrl(),
    api_token: localInfo.value.api_token,
  };
  await copyText(JSON.stringify(payload));
  message.success(t('cluster.pairingCopied'));
}

function scrollToLocalCard() {
  const el = localCardRef.value?.$el || localCardRef.value;
  if (el?.scrollIntoView) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

function resetNodeForm() {
  Object.assign(nodeForm, {
    id: 0,
    name: '',
    region: '',
    region_flag: '',
    api_url: '',
    api_token: '',
    share_host_override: '',
    allow_insecure: false,
    enable: true,
    include_in_sub: true,
    node_prefix: '',
    remark: '',
    sort_order: remoteNodes.value.length,
  });
  testResult.value = null;
  testError.value = '';
  pairingInput.value = '';
  editingTokenPreview.value = '';
}

function openAddModal() {
  resetNodeForm();
  nodeModalOpen.value = true;
}

function openEditModal(item) {
  resetNodeForm();
  const n = item?.node || {};
  Object.assign(nodeForm, {
    id: n.id || 0,
    name: n.name || '',
    region: n.region || '',
    region_flag: n.region_flag || '',
    api_url: n.api_url || '',
    api_token: '',
    share_host_override: n.share_host_override || '',
    allow_insecure: Boolean(n.allow_insecure),
    enable: n.enable !== false,
    include_in_sub: n.include_in_sub !== false,
    node_prefix: n.node_prefix || '',
    remark: n.remark || '',
    sort_order: n.sort_order || 0,
  });
  editingTokenPreview.value = item?.token_preview || '';
  nodeModalOpen.value = true;
}

function onPairingPaste(e) {
  const text = e.clipboardData?.getData('text') || '';
  if (text.trim().startsWith('{')) {
    setTimeout(() => applyPairingCode(text), 0);
  }
}

function applyPairingCode(raw) {
  const txt = (raw || '').trim();
  if (!txt) return;
  try {
    const obj = JSON.parse(txt);
    if (!obj || typeof obj !== 'object' || (!obj.api_url && !obj.api_token)) {
      throw new Error('invalid');
    }
    if (obj.api_url) nodeForm.api_url = String(obj.api_url).trim();
    if (obj.api_token) nodeForm.api_token = String(obj.api_token).trim();
    if (obj.name) nodeForm.name = String(obj.name).trim();
    if (obj.region) nodeForm.region = String(obj.region).trim();
    if (obj.region_flag) nodeForm.region_flag = String(obj.region_flag).trim();
    testResult.value = null;
    testError.value = '';
    message.success(t('cluster.pairingParsed'));
  } catch {
    message.error(t('cluster.pairingInvalid'));
  }
}

async function handleTestNode() {
  if (!nodeForm.api_url.trim()) {
    message.warning(t('cluster.apiUrl'));
    return;
  }
  testingNode.value = true;
  testResult.value = null;
  testError.value = '';
  try {
    const res = await api.clusterTestNode({
      node_id: nodeForm.id,
      api_url: nodeForm.api_url.trim(),
      api_token: nodeForm.api_token.trim(),
      allow_insecure: nodeForm.allow_insecure,
    });
    testResult.value = res;
    if (!nodeForm.name.trim() && res.local_name) {
      nodeForm.name = res.local_name;
    }
    if (!nodeForm.region.trim() && res.local_region) {
      nodeForm.region = res.local_region;
    }
    if (!nodeForm.region_flag.trim() && res.local_region_flag) {
      nodeForm.region_flag = res.local_region_flag;
    }
  } catch (e) {
    testError.value = e.message;
  } finally {
    testingNode.value = false;
  }
}

async function handleSaveNode() {
  savingNode.value = true;
  try {
    await api.clusterSaveNode({ ...nodeForm });
    message.success(t('app.saveSuccess'));
    nodeModalOpen.value = false;
    await loadOverview(true);
  } catch (e) {
    message.error(e.message);
  } finally {
    savingNode.value = false;
  }
}

async function handleDeleteNode(id) {
  try {
    await api.clusterDeleteNode(id);
    message.success(t('cluster.nodeDeleted'));
    await loadOverview(true);
  } catch (e) {
    message.error(e.message);
  }
}

let pollTimer = null;
onMounted(() => {
  loadOverview(false);
  pollTimer = setInterval(() => loadOverview(true), 10000);
});

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>

<style scoped>
.cluster-kpi-card {
  height: 100%;
}

.cluster-kpi-label {
  font-size: 12px;
  opacity: 0.72;
  margin-bottom: 6px;
}

.cluster-kpi-value {
  font-size: 22px;
  font-weight: 600;
  line-height: 1.25;
  margin-bottom: 6px;
}

.cluster-kpi-speed {
  font-size: 16px;
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.cluster-kpi-accent {
  color: var(--ant-color-primary, #1677ff);
}

.cluster-kpi-muted {
  font-size: 15px;
  opacity: 0.58;
  font-weight: 400;
}

.cluster-kpi-sub {
  font-size: 12px;
  opacity: 0.75;
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.cluster-region-tags {
  display: inline-flex;
  gap: 4px;
  flex-wrap: wrap;
}

.cluster-node-cell {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.cluster-node-title {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.cluster-flag {
  font-size: 16px;
  line-height: 1;
}

.cluster-node-meta {
  font-size: 12px;
  opacity: 0.72;
  word-break: break-all;
}

.cluster-sub-line {
  font-size: 12px;
  opacity: 0.72;
}

.cluster-err-line {
  font-size: 11px;
  color: #ff4d4f;
  max-width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cluster-empty-hint {
  padding: 12px 16px;
  font-size: 12px;
  opacity: 0.75;
  border-top: 1px solid var(--panel-line, rgba(128, 128, 128, 0.16));
}

.cluster-section-title {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 10px;
}
</style>
