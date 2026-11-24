<template>
  <a-card size="small">
    <a-tabs v-model:activeKey="activeTab">
      <!-- Tab 1: Active Connections -->
      <a-tab-pane key="conns" :tab="`${t('conns.activeTab')} (${filteredConns.length})`">
        <div style="display: flex; justify-content: space-between; margin-bottom: 12px; gap: 10px; flex-wrap: wrap">
          <a-space>
            <a-switch v-model:checked="autoRefresh" size="small" />
            <span style="font-size: 13px">{{ t('conns.autoRefresh') }}</span>
            <a-button size="small" @click="fetchConns">↻ {{ t('app.refresh') }}</a-button>
            <a-popconfirm title="Close all active connections?" @confirm="closeAll">
              <a-button size="small" danger>{{ t('conns.closeAll') }}</a-button>
            </a-popconfirm>
          </a-space>

          <a-input-search v-model:value="connSearch" placeholder="Filter host / IP / inbound..." style="width: 240px" size="small" allow-clear />
        </div>

        <a-table
          :data-source="filteredConns"
          :columns="connCols"
          row-key="id"
          size="small"
          :pagination="{ pageSize: 20 }"
          :scroll="{ x: 860 }"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'inbound'">
              <a-tag color="geekblue">{{ record.metadata?.inboundName || '-' }}</a-tag>
              <a-tag>{{ record.metadata?.network }}</a-tag>
            </template>
            <template v-else-if="column.key === 'source'">
              <code>{{ record.metadata?.sourceIP }}:{{ record.metadata?.sourcePort }}</code>
            </template>
            <template v-else-if="column.key === 'dest'">
              <b>{{ record.metadata?.host || record.metadata?.destinationIP }}</b>:{{ record.metadata?.destinationPort }}
            </template>
            <template v-else-if="column.key === 'chain'">
              <a-tag color="purple">{{ (record.chains || []).join(' ← ') || 'DIRECT' }}</a-tag>
            </template>
            <template v-else-if="column.key === 'traffic'">
              ↑ {{ formatBytes(record.upload) }} / ↓ {{ formatBytes(record.download) }}
            </template>
            <template v-else-if="column.key === 'actions'">
              <a-button size="small" danger type="link" @click="closeOne(record.id)">✕</a-button>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- Tab 2: Live Shoes Logs -->
      <a-tab-pane key="logs" :tab="t('conns.logsTab')">
        <div style="display: flex; justify-content: space-between; margin-bottom: 10px; flex-wrap: wrap; gap: 8px">
          <a-space>
            <a-select v-model:value="streamFilter" size="small" style="width: 120px">
              <a-select-option value="">All Streams</a-select-option>
              <a-select-option value="stdout">stdout</a-select-option>
              <a-select-option value="stderr">stderr</a-select-option>
              <a-select-option value="panel">panel</a-select-option>
            </a-select>
            <a-input v-model:value="logSearch" placeholder="Filter logs..." size="small" style="width: 220px" allow-clear />
          </a-space>

          <a-space>
            <a-button size="small" @click="fetchLogs">↻ {{ t('app.refresh') }}</a-button>
            <a-button size="small" danger @click="clearLogs">{{ t('conns.clearLogs') }}</a-button>
          </a-space>
        </div>

        <div class="log-terminal">
          <div v-if="filteredLogs.length === 0" style="opacity: 0.5">No log entries yet.</div>
          <div v-for="l in filteredLogs" :key="l.seq" class="log-line">
            <span class="log-time">[{{ l.time }}]</span>
            <span :class="'log-tag log-' + l.stream">[{{ l.stream }}]</span>
            <span>{{ l.line }}</span>
          </div>
        </div>
      </a-tab-pane>
    </a-tabs>
  </a-card>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { formatBytes } from '../utils';

const { t } = useI18n();
const activeTab = ref('conns');
const autoRefresh = ref(true);

const conns = ref([]);
const connSearch = ref('');

const logs = ref([]);
const streamFilter = ref('');
const logSearch = ref('');

const connCols = computed(() => [
  { title: t('conns.inboundTag'), key: 'inbound', width: 170 },
  { title: t('conns.source'), key: 'source', width: 170 },
  { title: t('conns.destination'), key: 'dest', ellipsis: true },
  { title: t('conns.chain'), key: 'chain', width: 160 },
  { title: 'Traffic', key: 'traffic', width: 180 },
  { title: '', key: 'actions', width: 55 },
]);

const filteredConns = computed(() => {
  const q = connSearch.value.trim().toLowerCase();
  if (!q) return conns.value;
  return conns.value.filter((c) => JSON.stringify(c.metadata || {}).toLowerCase().includes(q));
});

const filteredLogs = computed(() => {
  const q = logSearch.value.trim().toLowerCase();
  return logs.value.filter((l) => {
    if (streamFilter.value && l.stream !== streamFilter.value) return false;
    if (q && !l.line.toLowerCase().includes(q)) return false;
    return true;
  });
});

async function fetchConns() {
  const res = await api.clashConnections().catch(() => ({ connections: [] }));
  conns.value = res?.connections || [];
}

async function fetchLogs() {
  logs.value = await api.shoesLogs(0, 400).catch(() => []);
}

async function closeOne(id) {
  await api.clashCloseOne(id);
  await fetchConns();
}

async function closeAll() {
  await api.clashCloseAll();
  message.success('Closed all connections');
  await fetchConns();
}

async function clearLogs() {
  await api.shoesClearLogs();
  logs.value = [];
}

let timer = null;
onMounted(() => {
  fetchConns();
  fetchLogs();
  timer = setInterval(() => {
    if (!autoRefresh.value) return;
    if (activeTab.value === 'conns') fetchConns();
    else fetchLogs();
  }, 2000);
});

onUnmounted(() => {
  if (timer) clearInterval(timer);
});
</script>

<style scoped>
.log-terminal {
  height: 62vh;
  overflow-y: auto;
  background: #11161d;
  color: #dbe4ee;
  padding: 12px;
  border-radius: 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.55;
}
.log-line {
  word-break: break-all;
}
.log-time {
  color: #7c8b9e;
  margin-right: 6px;
}
.log-tag {
  margin-right: 8px;
  font-weight: 600;
}
.log-stdout {
  color: #52c41a;
}
.log-stderr {
  color: #faad14;
}
.log-panel {
  color: #4096ff;
}
</style>
