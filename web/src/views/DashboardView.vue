<template>
  <div class="dashboard">
    <div class="resource-grid">
      <a-card v-for="resource in resources" :key="resource.title" size="small" class="resource-card">
        <div class="resource-copy">
          <h2>{{ resource.title }}</h2>
          <p>{{ resource.detail }}</p>
        </div>
        <div class="resource-gauge" :style="{ '--gauge-color': gaugeColor(resource.percent) }">
          <a-progress
            type="circle"
            :percent="resource.percent"
            :size="54"
            :stroke-width="7"
            stroke-color="var(--gauge-color)"
            trail-color="var(--panel-line)"
            :show-info="false"
            aria-hidden="true"
          />
          <span>{{ resource.percent }}%</span>
        </div>
      </a-card>
    </div>

    <div class="dashboard-details">
      <a-card size="small" class="dashboard-section service-card">
        <template #title><h2>{{ t('dashboard.shoesService') }}</h2></template>
        <template #extra>
          <span class="panel-status" :class="{ 'panel-status--running': shoes.running }">
            {{ t(shoes.running ? 'dashboard.running' : 'dashboard.stopped') }}
          </span>
        </template>

        <a-alert
          v-if="!shoes.bin_exists"
          type="warning"
          show-icon
          :message="t('dashboard.binMissing')"
        />
        <a-alert v-else-if="shoes.last_error" type="error" show-icon :message="shoes.last_error" />

        <dl class="detail-list">
          <div>
            <dt>{{ t('dashboard.version') }}</dt>
            <dd><code>{{ shoes.version || '—' }}</code></dd>
          </div>
          <div>
            <dt>{{ t('dashboard.pid') }}</dt>
            <dd>{{ shoes.pid || '—' }}</dd>
          </div>
          <div>
            <dt>{{ t('dashboard.shoesMem') }}</dt>
            <dd>{{ sys.shoes_rss_bytes ? formatBytes(sys.shoes_rss_bytes) : '—' }}</dd>
          </div>
          <div>
            <dt>{{ t('dashboard.clashApi') }}</dt>
            <dd><a-badge :status="sys.clash_online ? 'success' : 'default'" :text="sys.clash_online ? 'Online' : 'Offline'" /></dd>
          </div>
          <div>
            <dt>{{ t('dashboard.inboundsCount') }}</dt>
            <dd>{{ totals.inbounds_enabled || 0 }} / {{ totals.inbounds_total || 0 }}</dd>
          </div>
          <div>
            <dt>{{ t('dashboard.clientsCount') }}</dt>
            <dd>{{ totals.clients_total || 0 }}</dd>
          </div>
        </dl>

        <div class="service-actions">
          <a-button
            v-if="!shoes.running"
            type="primary"
            :loading="opLoading === 'start'"
            :disabled="Boolean(opLoading && opLoading !== 'start')"
            @click="doOp('start')"
          >
            <template #icon><CaretRightOutlined /></template>
            {{ t('dashboard.start') }}
          </a-button>
          <a-button
            v-else
            danger
            :loading="opLoading === 'stop'"
            :disabled="Boolean(opLoading && opLoading !== 'stop')"
            @click="doOp('stop')"
          >
            <template #icon><PauseOutlined /></template>
            {{ t('dashboard.stop') }}
          </a-button>
          <a-button :loading="opLoading === 'restart'" :disabled="Boolean(opLoading && opLoading !== 'restart')" @click="doOp('restart')">
            <template #icon><RedoOutlined /></template>
            {{ t('dashboard.restart') }}
          </a-button>
          <a-button :loading="opLoading === 'reload'" :disabled="Boolean(opLoading && opLoading !== 'reload')" @click="doOp('reload')">
            <template #icon><ThunderboltOutlined /></template>
            {{ t('dashboard.reload') }}
          </a-button>
          <a-button @click="openYamlPreview">
            <template #icon><FileTextOutlined /></template>
            {{ t('dashboard.previewYaml') }}
          </a-button>
        </div>
      </a-card>

      <a-card size="small" class="dashboard-section">
        <template #title><h2>{{ t('dashboard.netSpeed') }}</h2></template>
        <div class="throughput-grid">
          <section v-for="metric in throughput" :key="metric.title" class="throughput-tile">
            <h3>{{ metric.title }}</h3>
            <dl class="throughput-pair">
              <div>
                <dt><ArrowUpOutlined aria-hidden="true" /> {{ t('dashboard.upload') }}</dt>
                <dd>{{ metric.up }}</dd>
              </div>
              <div>
                <dt><ArrowDownOutlined aria-hidden="true" /> {{ t('dashboard.download') }}</dt>
                <dd>{{ metric.down }}</dd>
              </div>
            </dl>
          </section>
          <section class="throughput-tile">
            <h3>{{ t('dashboard.activeConns') }}</h3>
            <p class="connection-count">{{ sys.active_connections || 0 }}</p>
          </section>
        </div>
      </a-card>
    </div>

    <a-card size="small" class="dashboard-section">
      <template #title><h2>{{ t('dashboard.sysInfo') }}</h2></template>
      <dl class="detail-list host-details">
        <div>
          <dt>{{ t('dashboard.os') }}</dt>
          <dd>{{ sys.os_name || '—' }} {{ sys.kernel_version ? `(${sys.kernel_version})` : '' }}</dd>
        </div>
        <div>
          <dt>{{ t('dashboard.arch') }}</dt>
          <dd>{{ sys.arch || '—' }}</dd>
        </div>
        <div>
          <dt>{{ t('dashboard.hostUptime') }}</dt>
          <dd>{{ formatDuration(sys.host_uptime_secs, locale === 'zh') }}</dd>
        </div>
        <div>
          <dt>{{ t('dashboard.panelUptime') }}</dt>
          <dd>{{ formatDuration(sys.panel_uptime_secs, locale === 'zh') }}</dd>
        </div>
      </dl>
    </a-card>

    <a-modal v-model:open="yamlModalOpen" :title="yamlPath || 'shoes.config.yaml'" width="760px" :footer="null">
      <div class="yaml-actions">
        <a-button size="small" type="primary" @click="copyYaml">{{ t('dashboard.copyYaml') }}</a-button>
      </div>
      <pre class="yaml-preview">{{ yamlContent }}</pre>
    </a-modal>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue';
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  CaretRightOutlined,
  FileTextOutlined,
  PauseOutlined,
  RedoOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons-vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { copyText, formatBytes, formatDuration, formatSpeed } from '../utils';

const props = defineProps({
  statusData: { type: Object, default: () => ({}) },
});
const emit = defineEmits(['refresh']);
const { t, locale } = useI18n();

const sys = computed(() => props.statusData?.system || {});
const shoes = computed(() => props.statusData?.shoes || {});
const totals = computed(() => props.statusData?.totals || {});

const resources = computed(() => [
  {
    title: t('dashboard.cpu'),
    detail: `${sys.value.cpu_cores || 1} ${t('dashboard.cores')}`,
    percent: Math.round(sys.value.cpu_usage || 0),
  },
  {
    title: t('dashboard.memory'),
    detail: `${formatBytes(sys.value.mem_used)} / ${formatBytes(sys.value.mem_total)}`,
    percent: pct(sys.value.mem_used, sys.value.mem_total),
  },
  {
    title: t('dashboard.swap'),
    detail: `${formatBytes(sys.value.swap_used)} / ${formatBytes(sys.value.swap_total)}`,
    percent: pct(sys.value.swap_used, sys.value.swap_total),
  },
  {
    title: t('dashboard.disk'),
    detail: `${formatBytes(sys.value.disk_used)} / ${formatBytes(sys.value.disk_total)}`,
    percent: pct(sys.value.disk_used, sys.value.disk_total),
  },
]);

const throughput = computed(() => [
  {
    title: t('dashboard.proxyNet'),
    up: formatSpeed(sys.value.proxy_up_speed),
    down: formatSpeed(sys.value.proxy_down_speed),
  },
  {
    title: t('dashboard.totalTraffic'),
    up: formatBytes(totals.value.up_bytes),
    down: formatBytes(totals.value.down_bytes),
  },
  {
    title: t('dashboard.hostNet'),
    up: formatSpeed(sys.value.net_tx_speed),
    down: formatSpeed(sys.value.net_rx_speed),
  },
]);

const opLoading = ref('');
const yamlModalOpen = ref(false);
const yamlContent = ref('');
const yamlPath = ref('');

function pct(used, total) {
  if (!total || total <= 0) return 0;
  return Math.min(100, Math.round((used / total) * 100));
}

function gaugeColor(p) {
  if (p >= 85) return 'var(--panel-danger)';
  if (p >= 65) return 'var(--panel-warning)';
  return 'var(--panel-accent)';
}

async function doOp(action) {
  if (opLoading.value) return;
  opLoading.value = action;
  try {
    if (action === 'start') await api.shoesStart();
    else if (action === 'stop') await api.shoesStop();
    else if (action === 'restart') await api.shoesRestart();
    else if (action === 'reload') await api.shoesReload();
    message.success('OK');
    emit('refresh');
  } catch (e) {
    message.error(e.message);
  } finally {
    opLoading.value = '';
  }
}

async function openYamlPreview() {
  try {
    const res = await api.shoesConfigPreview();
    yamlContent.value = res.yaml;
    yamlPath.value = res.path;
    yamlModalOpen.value = true;
  } catch (e) {
    message.error(e.message);
  }
}

async function copyYaml() {
  await copyText(yamlContent.value);
  message.success(t('app.copied'));
}
</script>

<style scoped>
.dashboard {
  display: grid;
  gap: var(--panel-gap);
  font-variant-numeric: tabular-nums;
}

.resource-grid,
.dashboard-details {
  display: grid;
  gap: var(--panel-gap);
}

.resource-grid {
  grid-template-columns: repeat(4, minmax(0, 1fr));
}

.dashboard-details {
  grid-template-columns: minmax(0, 1.12fr) minmax(0, 1fr);
}

.dashboard-section :deep(.ant-card-body),
.resource-card :deep(.ant-card-body) {
  padding: var(--panel-space-5);
}

.resource-card :deep(.ant-card-body) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--panel-space-3);
  min-block-size: 6.25rem;
}

.resource-copy {
  min-inline-size: 0;
}

.resource-copy h2,
.dashboard-section h2 {
  margin: 0;
  color: var(--panel-text);
  font-size: 1rem;
  font-weight: 650;
  letter-spacing: -0.015em;
}

.resource-copy p {
  margin: 0.25rem 0 0;
  color: var(--panel-muted);
  font-size: 0.8125rem;
  line-height: 1.4;
  overflow-wrap: anywhere;
}

.resource-gauge {
  position: relative;
  display: grid;
  place-items: center;
  flex: none;
}

.resource-gauge :deep(.ant-progress) {
  line-height: 0;
}

.resource-gauge > span {
  position: absolute;
  color: var(--gauge-color);
  font-size: 0.8125rem;
  font-weight: 700;
}

.resource-gauge :deep(.ant-progress-circle-path) {
  transition: stroke-dashoffset var(--panel-motion-view) var(--panel-ease),
    stroke var(--panel-motion-mid) var(--panel-ease);
}

.dashboard-section :deep(.ant-card-head) {
  padding-inline: var(--panel-space-5);
}

.dashboard-section :deep(.ant-card-head-wrapper) {
  gap: var(--panel-space-2);
}

.service-card {
  display: flex;
  flex-direction: column;
}

.service-card :deep(.ant-card-body) {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: var(--panel-space-4);
}

.detail-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1px;
  margin: 0;
  background: var(--panel-line);
  border: 1px solid var(--panel-line);
  border-radius: var(--panel-control-radius);
  overflow: hidden;
}

.detail-list > div {
  padding: var(--panel-space-3);
  background: var(--panel-inset);
}

.detail-list dt,
.throughput-pair dt {
  color: var(--panel-muted);
  font-size: 0.8125rem;
}

.detail-list dd {
  margin: 0.25rem 0 0;
  font-weight: 600;
  overflow-wrap: anywhere;
}

.service-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--panel-space-2);
  margin-block-start: auto;
}

.service-actions :deep(.ant-btn) {
  min-block-size: 2.75rem;
  height: auto;
  white-space: normal;
}

.throughput-grid,
.throughput-pair {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--panel-space-2);
}

.throughput-tile {
  padding: var(--panel-space-3);
  background: var(--panel-inset);
  border-radius: var(--panel-control-radius);
}

.throughput-tile h3 {
  margin: 0 0 var(--panel-space-2);
  color: var(--panel-text);
  font-size: 0.875rem;
  font-weight: 650;
}

.throughput-pair {
  margin: 0;
}

.throughput-pair dt .anticon {
  color: var(--panel-accent);
}

.throughput-pair > div + div dt .anticon {
  color: var(--panel-success);
}

.throughput-pair dd,
.connection-count {
  margin: 0.125rem 0 0;
  font-size: 1rem;
  font-weight: 650;
  line-height: 1.3;
  overflow-wrap: anywhere;
}

.connection-count {
  font-size: 1.375rem;
}

.host-details {
  grid-template-columns: repeat(4, minmax(0, 1fr));
}

.yaml-actions {
  display: flex;
  justify-content: flex-end;
  margin-block-end: var(--panel-space-2);
}

.yaml-preview {
  max-block-size: 62vh;
  overflow: auto;
  padding: var(--panel-space-4);
  border-radius: var(--panel-control-radius);
  background: var(--panel-inset);
  font-size: 0.8125rem;
  margin: 0;
}

@container panel (max-width: 53rem) {
  .resource-grid,
  .host-details {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .dashboard-details {
    grid-template-columns: minmax(0, 1fr);
  }
}

@container panel (max-width: 25rem) {
  .resource-grid,
  .throughput-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
