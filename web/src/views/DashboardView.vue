<template>
  <div style="display: flex; flex-direction: column; gap: 16px">
    <!-- Top 4 System Resource Gauges -->
    <a-row :gutter="[16, 16]">
      <a-col :xs="24" :sm="12" :lg="6">
        <a-card size="small" class="stat-card">
          <div class="gauge-wrap">
            <a-progress
              type="dashboard"
              :percent="Math.round(sys.cpu_usage || 0)"
              :size="96"
              :stroke-color="gaugeColor(sys.cpu_usage)"
            />
            <div>
              <div class="stat-label">{{ t('dashboard.cpu') }}</div>
              <div class="stat-sub">{{ sys.cpu_cores || 1 }} {{ t('dashboard.cores') }}</div>
            </div>
          </div>
        </a-card>
      </a-col>

      <a-col :xs="24" :sm="12" :lg="6">
        <a-card size="small" class="stat-card">
          <div class="gauge-wrap">
            <a-progress
              type="dashboard"
              :percent="pct(sys.mem_used, sys.mem_total)"
              :size="96"
              :stroke-color="gaugeColor(pct(sys.mem_used, sys.mem_total))"
            />
            <div>
              <div class="stat-label">{{ t('dashboard.memory') }}</div>
              <div class="stat-sub">{{ formatBytes(sys.mem_used) }} / {{ formatBytes(sys.mem_total) }}</div>
            </div>
          </div>
        </a-card>
      </a-col>

      <a-col :xs="24" :sm="12" :lg="6">
        <a-card size="small" class="stat-card">
          <div class="gauge-wrap">
            <a-progress
              type="dashboard"
              :percent="pct(sys.swap_used, sys.swap_total)"
              :size="96"
              :stroke-color="gaugeColor(pct(sys.swap_used, sys.swap_total))"
            />
            <div>
              <div class="stat-label">{{ t('dashboard.swap') }}</div>
              <div class="stat-sub">{{ formatBytes(sys.swap_used) }} / {{ formatBytes(sys.swap_total) }}</div>
            </div>
          </div>
        </a-card>
      </a-col>

      <a-col :xs="24" :sm="12" :lg="6">
        <a-card size="small" class="stat-card">
          <div class="gauge-wrap">
            <a-progress
              type="dashboard"
              :percent="pct(sys.disk_used, sys.disk_total)"
              :size="96"
              :stroke-color="gaugeColor(pct(sys.disk_used, sys.disk_total))"
            />
            <div>
              <div class="stat-label">{{ t('dashboard.disk') }}</div>
              <div class="stat-sub">{{ formatBytes(sys.disk_used) }} / {{ formatBytes(sys.disk_total) }}</div>
            </div>
          </div>
        </a-card>
      </a-col>
    </a-row>

    <!-- Shoes Core Service Control & Live Throughput -->
    <a-row :gutter="[16, 16]">
      <a-col :xs="24" :lg="13">
        <a-card :title="t('dashboard.shoesService')" size="small">
          <template #extra>
            <a-tag :color="shoes.running ? 'success' : 'error'">
              {{ shoes.running ? '● ' + t('dashboard.running') : '○ ' + t('dashboard.stopped') }}
            </a-tag>
          </template>

          <a-alert
            v-if="!shoes.bin_exists"
            type="warning"
            show-icon
            :message="t('dashboard.binMissing')"
            style="margin-bottom: 12px"
          />
          <a-alert
            v-else-if="shoes.last_error"
            type="error"
            show-icon
            :message="shoes.last_error"
            style="margin-bottom: 12px"
          />

          <a-descriptions :column="{ xs: 1, sm: 2 }" size="small" bordered>
            <a-descriptions-item :label="t('dashboard.version')">
              <code>{{ shoes.version || '-' }}</code>
            </a-descriptions-item>
            <a-descriptions-item :label="t('dashboard.pid')">
              {{ shoes.pid || '-' }}
            </a-descriptions-item>
            <a-descriptions-item :label="t('dashboard.shoesMem')">
              {{ sys.shoes_rss_bytes ? formatBytes(sys.shoes_rss_bytes) : '-' }}
            </a-descriptions-item>
            <a-descriptions-item :label="t('dashboard.clashApi')">
              <a-badge :status="sys.clash_online ? 'success' : 'default'" :text="sys.clash_online ? 'Online' : 'Offline'" />
            </a-descriptions-item>
            <a-descriptions-item :label="t('dashboard.inboundsCount')">
              <b>{{ totals.inbounds_enabled || 0 }}</b> / {{ totals.inbounds_total || 0 }}
            </a-descriptions-item>
            <a-descriptions-item :label="t('dashboard.clientsCount')">
              <b>{{ totals.clients_total || 0 }}</b>
            </a-descriptions-item>
          </a-descriptions>

          <a-space wrap style="margin-top: 14px">
            <a-button v-if="!shoes.running" type="primary" :loading="opLoading" @click="doOp('start')">
              ▶ {{ t('dashboard.start') }}
            </a-button>
            <a-button v-else danger :loading="opLoading" @click="doOp('stop')">
              ■ {{ t('dashboard.stop') }}
            </a-button>
            <a-button :loading="opLoading" @click="doOp('restart')">
              ↻ {{ t('dashboard.restart') }}
            </a-button>
            <a-button type="dashed" :loading="opLoading" @click="doOp('reload')">
              ⚡ {{ t('dashboard.reload') }}
            </a-button>
            <a-button @click="openYamlPreview">
              📄 {{ t('dashboard.previewYaml') }}
            </a-button>
          </a-space>
        </a-card>
      </a-col>

      <a-col :xs="24" :lg="11">
        <a-card :title="t('dashboard.netSpeed')" size="small">
          <a-row :gutter="[12, 12]">
            <a-col :span="12">
              <div class="metric-tile">
                <div class="metric-caption">{{ t('dashboard.proxyNet') }} ↑</div>
                <div class="metric-val" style="color: #1677ff">{{ formatSpeed(sys.proxy_up_speed) }}</div>
              </div>
            </a-col>
            <a-col :span="12">
              <div class="metric-tile">
                <div class="metric-caption">{{ t('dashboard.proxyNet') }} ↓</div>
                <div class="metric-val" style="color: #52c41a">{{ formatSpeed(sys.proxy_down_speed) }}</div>
              </div>
            </a-col>
            <a-col :span="12">
              <div class="metric-tile">
                <div class="metric-caption">{{ t('dashboard.totalTraffic') }} ↑</div>
                <div class="metric-val">{{ formatBytes(totals.up_bytes) }}</div>
              </div>
            </a-col>
            <a-col :span="12">
              <div class="metric-tile">
                <div class="metric-caption">{{ t('dashboard.totalTraffic') }} ↓</div>
                <div class="metric-val">{{ formatBytes(totals.down_bytes) }}</div>
              </div>
            </a-col>
            <a-col :span="12">
              <div class="metric-tile">
                <div class="metric-caption">{{ t('dashboard.hostNet') }}</div>
                <div style="font-size: 13px; font-weight: 600">
                  ↑ {{ formatSpeed(sys.net_tx_speed) }} · ↓ {{ formatSpeed(sys.net_rx_speed) }}
                </div>
              </div>
            </a-col>
            <a-col :span="12">
              <div class="metric-tile">
                <div class="metric-caption">{{ t('dashboard.activeConns') }}</div>
                <div class="metric-val" style="color: #722ed1">{{ sys.active_connections || 0 }}</div>
              </div>
            </a-col>
          </a-row>
        </a-card>
      </a-col>
    </a-row>

    <!-- System Info -->
    <a-card :title="t('dashboard.sysInfo')" size="small">
      <a-descriptions :column="{ xs: 1, sm: 2, md: 4 }" size="small">
        <a-descriptions-item :label="t('dashboard.os')">
          {{ sys.os_name || '-' }} {{ sys.kernel_version ? `(${sys.kernel_version})` : '' }}
        </a-descriptions-item>
        <a-descriptions-item :label="t('dashboard.arch')">
          <a-tag>{{ sys.arch || '-' }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item :label="t('dashboard.hostUptime')">
          {{ formatDuration(sys.host_uptime_secs, locale === 'zh') }}
        </a-descriptions-item>
        <a-descriptions-item :label="t('dashboard.panelUptime')">
          {{ formatDuration(sys.panel_uptime_secs, locale === 'zh') }}
        </a-descriptions-item>
      </a-descriptions>
    </a-card>

    <!-- YAML Preview Modal -->
    <a-modal
      v-model:open="yamlModalOpen"
      :title="yamlPath || 'shoes.config.yaml'"
      width="760px"
      :footer="null"
    >
      <div style="display: flex; justify-content: flex-end; margin-bottom: 8px">
        <a-button size="small" type="primary" @click="copyYaml">Copy YAML</a-button>
      </div>
      <pre
        style="max-height: 62vh; overflow: auto; padding: 14px; border-radius: 8px; background: rgba(127,127,127,0.12); font-size: 12px; margin: 0"
      >{{ yamlContent }}</pre>
    </a-modal>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue';
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

const opLoading = ref(false);
const yamlModalOpen = ref(false);
const yamlContent = ref('');
const yamlPath = ref('');

function pct(used, total) {
  if (!total || total <= 0) return 0;
  return Math.min(100, Math.round((used / total) * 100));
}

function gaugeColor(p) {
  if (p >= 85) return '#ff4d4f';
  if (p >= 65) return '#faad14';
  return '#1677ff';
}

async function doOp(action) {
  opLoading.value = true;
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
    opLoading.value = false;
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
.stat-card {
  border-radius: 12px;
}
.gauge-wrap {
  display: flex;
  align-items: center;
  gap: 16px;
}
.stat-label {
  font-weight: 600;
  font-size: 15px;
}
.stat-sub {
  font-size: 12px;
  opacity: 0.7;
  margin-top: 4px;
}
.metric-tile {
  padding: 10px 12px;
  border-radius: 8px;
  background: rgba(127, 127, 127, 0.07);
}
.metric-caption {
  font-size: 12px;
  opacity: 0.7;
  margin-bottom: 4px;
}
.metric-val {
  font-size: 17px;
  font-weight: 700;
}
</style>
