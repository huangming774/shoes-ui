<template>
  <div>
    <!-- Toolbar -->
    <a-card size="small" style="margin-bottom: 14px">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px">
        <a-space wrap>
          <a-button type="primary" @click="openCreate">
            + {{ t('inbounds.add') }}
          </a-button>
          <a-popconfirm :title="t('inbounds.resetAllConfirm')" @confirm="handleResetAll">
            <a-button>{{ t('inbounds.resetAll') }}</a-button>
          </a-popconfirm>
          <a-button @click="loadData">↻ {{ t('app.refresh') }}</a-button>
          <a-tag
            :color="currentShareHost === '127.0.0.1' ? 'error' : 'geekblue'"
            style="cursor: pointer; padding: 4px 10px; font-size: 12px"
            @click="openHostModal"
          >
            🌐 节点地址: <b>{{ currentShareHost }}</b> ✎
          </a-tag>
        </a-space>

        <a-space wrap>
          <a-select v-model:value="protoFilter" style="width: 150px" allow-clear placeholder="All Protocols">
            <a-select-option value="">All Protocols</a-select-option>
            <a-select-option v-for="p in protocolsPresent" :key="p" :value="p">
              {{ p.toUpperCase() }}
            </a-select-option>
          </a-select>
          <a-input-search
            v-model:value="search"
            :placeholder="t('app.search')"
            allow-clear
            style="width: 250px"
          />
        </a-space>
      </div>
    </a-card>

    <!-- Two-Layer Expandable Table: Inbound -> Clients -->
    <a-card size="small" :body-style="{ padding: 0 }">
      <a-table
        :data-source="filteredInbounds"
        :columns="columns"
        row-key="id"
        :loading="loading"
        :pagination="{ pageSize: 15, showSizeChanger: true }"
        size="middle"
        :scroll="{ x: 980 }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'enable'">
            <a-switch
              :checked="record.enable"
              size="small"
              @change="(v) => handleToggle(record, v)"
            />
          </template>

          <template v-else-if="column.key === 'remark'">
            <div style="font-weight: 600">{{ record.remark }}</div>
            <div style="font-size: 11px; opacity: 0.6">
              <code>{{ record.tag }}</code> ·
              <template v-if="record.protocol === 'portforward'">
                {{ (record.protocol_settings?.forward_targets || []).length }} target(s)
              </template>
              <template v-else>
                {{ record.clients?.length || 0 }} client(s)
              </template>
            </div>
          </template>

          <template v-else-if="column.key === 'protocol'">
            <a-tag :color="PROTOCOL_COLORS[record.protocol] || 'blue'" style="font-weight: 600">
              {{ record.protocol.toUpperCase() }}
            </a-tag>
          </template>

          <template v-else-if="column.key === 'port'">
            <div>
              <a-tag color="default" style="font-family: monospace; font-size: 13px; font-weight: 600">
                {{ record.port }}
              </a-tag>
              <div v-if="record.protocol_settings?.port_range?.trim()" style="margin-top: 3px">
                <a-tag color="blue" style="font-family: monospace; font-size: 11px; margin: 0">
                  ⇄ {{ record.protocol_settings.port_range.trim() }}
                </a-tag>
              </div>
            </div>
          </template>

          <template v-else-if="column.key === 'transport'">
            <a-space v-if="record.protocol === 'portforward'" :size="4" wrap>
              <a-tag color="blue">FORWARD</a-tag>
              <a-tag
                v-for="(tgt, ti) in (record.protocol_settings?.forward_targets || []).slice(0, 2)"
                :key="ti"
                style="font-family: monospace; font-size: 11px"
              >
                → {{ tgt }}
              </a-tag>
              <a-tag v-if="(record.protocol_settings?.forward_targets || []).length > 2" color="default">
                +{{ (record.protocol_settings?.forward_targets || []).length - 2 }}
              </a-tag>
            </a-space>
            <a-space v-else :size="4" wrap>
              <a-tag>{{ transportLabel(record) }}</a-tag>
              <a-tag v-if="securityLabel(record)" :color="securityColor(record)">
                {{ securityLabel(record) }}
              </a-tag>
              <a-tag v-if="hasVlessNativeEnc(record)" color="volcano">VLESS-ENC</a-tag>
              <a-tag v-if="hasMldsa65(record)" color="geekblue">ML-DSA-65</a-tag>
              <a-tag v-if="hasVision(record)" color="purple">Vision</a-tag>
              <a-tag v-if="hasH2Mux(record)" color="cyan">H2Mux</a-tag>
            </a-space>
          </template>

          <template v-else-if="column.key === 'traffic'">
            <div style="font-size: 12px">
              <span style="color: #1677ff">↑ {{ formatBytes(record.up_bytes) }}</span>
              <span style="margin: 0 4px; opacity: 0.4">/</span>
              <span style="color: #52c41a">↓ {{ formatBytes(record.down_bytes) }}</span>
            </div>
            <div v-if="record.total_quota_bytes > 0" style="margin-top: 2px">
              <a-progress
                :percent="quotaPct(record)"
                size="small"
                :status="quotaPct(record) >= 100 ? 'exception' : 'active'"
              />
              <div style="font-size: 11px; opacity: 0.65">
                {{ formatBytes(record.up_bytes + record.down_bytes) }} / {{ formatBytes(record.total_quota_bytes) }}
              </div>
            </div>
            <div v-else style="font-size: 11px; opacity: 0.55">
              Σ {{ formatBytes(record.up_bytes + record.down_bytes) }} ({{ t('inbounds.unlimited') }})
            </div>
          </template>

          <template v-else-if="column.key === 'online'">
            <a-tag :color="record.active_connections > 0 ? 'success' : 'default'">
              {{ record.active_connections || 0 }}
            </a-tag>
          </template>

          <template v-else-if="column.key === 'expiry'">
            <a-tag v-if="!record.expiry_time" color="default">{{ t('inbounds.neverExpire') }}</a-tag>
            <a-tag v-else-if="record.expiry_time <= Date.now()" color="error">
              {{ t('inbounds.expired') }}
            </a-tag>
            <a-tooltip v-else :title="formatDate(record.expiry_time)">
              <a-tag color="processing">
                {{ t('inbounds.daysLeft', { n: Math.ceil((record.expiry_time - Date.now()) / 86400000) }) }}
              </a-tag>
            </a-tooltip>
          </template>

          <template v-else-if="column.key === 'actions'">
            <a-space :size="6">
              <a-tooltip v-if="record.protocol !== 'portforward'" :title="t('inbounds.qrShare')">
                <a-button size="small" type="primary" ghost @click="openShare(record)">
                  QR
                </a-button>
              </a-tooltip>
              <a-button size="small" @click="openEdit(record)">
                {{ t('app.edit') }}
              </a-button>
              <a-tooltip :title="t('inbounds.cloneNewPort')">
                <a-button size="small" @click="openCloneModal(record)">
                  +Port
                </a-button>
              </a-tooltip>
              <a-dropdown>
                <a-button size="small">⋯</a-button>
                <template #overlay>
                  <a-menu>
                    <a-menu-item v-if="record.multi_user_supported && record.protocol !== 'portforward'" @click="openAddClient(record)">
                      + {{ t('inbounds.addClient') }}
                    </a-menu-item>
                    <a-menu-item @click="handleResetTraffic(record)">
                      ↺ {{ t('inbounds.resetTraffic') }}
                    </a-menu-item>
                    <a-menu-divider />
                    <a-menu-item danger @click="handleDelete(record)">
                      ✕ {{ t('app.delete') }}
                    </a-menu-item>
                  </a-menu>
                </template>
              </a-dropdown>
            </a-space>
          </template>
        </template>

        <!-- Expanded Second Layer: Clients Table / PortForward Targets -->
        <template #expandedRowRender="{ record }">
          <div v-if="record.protocol === 'portforward'" style="padding: 8px 14px">
            <div style="font-size: 12px; opacity: 0.8; margin-bottom: 8px">
              ℹ️ {{ t('inbounds.forwardTip') }}
            </div>
            <a-space wrap>
              <span style="font-size: 12px; font-weight: 600">Targets:</span>
              <a-tag
                v-for="(tgt, ti) in record.protocol_settings?.forward_targets || []"
                :key="ti"
                color="geekblue"
                style="font-family: monospace"
              >
                {{ tgt }}
              </a-tag>
              <a-tag v-if="record.protocol_settings?.rules_ref" color="purple">
                Outbound: {{ record.protocol_settings.rules_ref }}
              </a-tag>
            </a-space>
          </div>
          <div v-else style="padding: 6px 12px">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; gap: 8px; flex-wrap: wrap">
              <span style="font-size: 12px; opacity: 0.78">
                ℹ️ {{ record.multi_user_supported ? t('inbounds.multiUserHint') : t('inbounds.singleUserHint') }}
              </span>
              <a-space>
                <a-button
                  v-if="record.multi_user_supported"
                  size="small"
                  type="primary"
                  ghost
                  @click="openAddClient(record)"
                >
                  + {{ t('inbounds.addClient') }}
                </a-button>
                <a-button v-else size="small" type="dashed" @click="openCloneModal(record)">
                  ⚡ {{ t('inbounds.cloneNewPort') }}
                </a-button>
              </a-space>
            </div>

            <a-table
              :data-source="record.clients || []"
              :columns="clientColumns"
              row-key="id"
              :pagination="false"
              size="small"
            >
              <template #bodyCell="{ column, record: client, index }">
                <template v-if="column.key === 'enable'">
                  <a-badge :status="client.enable ? 'success' : 'default'" :text="client.enable ? 'ON' : 'OFF'" />
                </template>
                <template v-else-if="column.key === 'credential'">
                  <code style="font-size: 12px; cursor: pointer" @click="copyCred(record, client)">
                    {{ formatCred(record, client) }} 📋
                  </code>
                </template>
                <template v-else-if="column.key === 'sub_id'">
                  <a-tag color="geekblue">{{ client.sub_id || 'default' }}</a-tag>
                </template>
                <template v-else-if="column.key === 'actions'">
                  <a-space :size="6">
                    <a-button size="small" type="link" @click="openSingleClientShare(record, index)">
                      QR / Link
                    </a-button>
                    <a-button size="small" type="link" @click="openEditClient(record, client)">
                      {{ t('app.edit') }}
                    </a-button>
                    <a-popconfirm
                      v-if="(record.clients || []).length > 1"
                      :title="t('app.deleteConfirm')"
                      @confirm="handleDeleteClient(client)"
                    >
                      <a-button size="small" type="link" danger>{{ t('app.delete') }}</a-button>
                    </a-popconfirm>
                  </a-space>
                </template>
              </template>
            </a-table>
          </div>
        </template>
      </a-table>
    </a-card>

    <!-- Modals -->
    <InboundModal
      v-model:open="inboundModalOpen"
      :record="editingInbound"
      :certs="certs"
      :outbound-groups="outboundGroups"
      :dns-groups="dnsGroups"
      @saved="loadData"
      @certs-changed="loadCerts"
    />

    <ClientModal
      v-model:open="clientModalOpen"
      :inbound-id="activeInboundForClient?.id"
      :protocol="activeInboundForClient?.protocol"
      :cipher="activeInboundForClient?.protocol_settings?.cipher"
      :record="editingClient"
      @saved="loadData"
    />

    <QrShareModal
      v-model:open="shareModalOpen"
      :title="shareTitle"
      :items="shareItems"
    />

    <!-- Quick Dedicated-Port Client Clone Modal -->
    <a-modal
      v-model:open="cloneModalOpen"
      :title="t('inbounds.cloneModalTitle')"
      :confirm-loading="cloning"
      @ok="submitClone"
    >
      <a-alert type="info" show-icon :message="t('inbounds.cloneDesc')" style="margin-bottom: 14px" />
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :span="14">
            <a-form-item :label="t('app.remark')">
              <a-input v-model:value="cloneForm.remark" />
            </a-form-item>
          </a-col>
          <a-col :span="10">
            <a-form-item :label="t('inbounds.newPort')">
              <a-input-number v-model:value="cloneForm.port" :min="1" :max="65535" style="width: 100%" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.clientName')">
              <a-input v-model:value="cloneForm.client_name" placeholder="bob" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('inbounds.subGroup')">
              <a-input v-model:value="cloneForm.sub_id" placeholder="default" />
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>
    </a-modal>

    <!-- Quick Public Host Edit Modal -->
    <a-modal v-model:open="hostModalOpen" title="修改分享链接与订阅的公网 IP / 域名" @ok="savePublicHost">
      <a-form layout="vertical">
        <a-form-item
          label="服务器公网 IP 或域名 (不含端口)"
          extra="小火箭二维码、vless:// 链接和 Clash 订阅中的 server 地址均使用此值。切勿填写 127.0.0.1 或 0.0.0.0。"
        >
          <a-input v-model:value="editingPublicHost" placeholder="例如 203.0.113.88 或 node.example.com" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { message, Modal } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import dayjs from 'dayjs';
import { api } from '../api';
import { copyText, formatBytes, PROTOCOL_COLORS } from '../utils';
import InboundModal from '../components/InboundModal.vue';
import ClientModal from '../components/ClientModal.vue';
import QrShareModal from '../components/QrShareModal.vue';

const { t } = useI18n();

const loading = ref(false);
const inbounds = ref([]);
const certs = ref([]);
const outboundGroups = ref([]);
const dnsGroups = ref([]);
const search = ref('');
const protoFilter = ref('');

const inboundModalOpen = ref(false);
const editingInbound = ref(null);

const clientModalOpen = ref(false);
const activeInboundForClient = ref(null);
const editingClient = ref(null);

const shareModalOpen = ref(false);
const shareTitle = ref('');
const shareItems = ref([]);

const cloneModalOpen = ref(false);
const cloning = ref(false);
const cloneSourceId = ref(0);
const cloneForm = reactive({ remark: '', port: 20001, client_name: '', sub_id: 'default' });

const currentShareHost = ref('...');
const hostModalOpen = ref(false);
const editingPublicHost = ref('');

const columns = computed(() => [
  { title: t('app.enable'), key: 'enable', width: 70 },
  { title: t('app.remark'), key: 'remark', width: 190 },
  { title: t('inbounds.protocol'), key: 'protocol', width: 120 },
  { title: t('inbounds.port'), key: 'port', width: 90 },
  { title: t('inbounds.transport'), key: 'transport', width: 190 },
  { title: t('inbounds.traffic'), key: 'traffic', width: 210 },
  { title: t('inbounds.online'), key: 'online', width: 80 },
  { title: t('inbounds.expiry'), key: 'expiry', width: 120 },
  { title: t('app.actions'), key: 'actions', width: 220, fixed: 'right' },
]);

const clientColumns = computed(() => [
  { title: t('app.status'), key: 'enable', width: 90 },
  { title: t('inbounds.clientName'), dataIndex: 'name', key: 'name', width: 160 },
  { title: 'Credential', key: 'credential' },
  { title: 'subId', key: 'sub_id', width: 120 },
  { title: t('app.actions'), key: 'actions', width: 200 },
]);

const protocolsPresent = computed(() => [...new Set(inbounds.value.map((i) => i.protocol))]);

const filteredInbounds = computed(() => {
  const q = search.value.trim().toLowerCase();
  return inbounds.value.filter((ib) => {
    if (protoFilter.value && ib.protocol !== protoFilter.value) return false;
    if (!q) return true;
    if (
      ib.remark.toLowerCase().includes(q) ||
      String(ib.port).includes(q) ||
      ib.protocol.toLowerCase().includes(q) ||
      ib.tag.toLowerCase().includes(q)
    ) {
      return true;
    }
    return (ib.clients || []).some(
      (c) =>
        (c.name || '').toLowerCase().includes(q) ||
        (c.sub_id || '').toLowerCase().includes(q) ||
        (c.uuid || '').toLowerCase().includes(q)
    );
  });
});

async function loadCerts() {
  certs.value = await api.listCerts().catch(() => []);
}

async function loadData() {
  loading.value = true;
  try {
    const [ibs, cs, gs, dgs, st] = await Promise.all([
      api.listInbounds(),
      api.listCerts().catch(() => []),
      api.listOutboundGroups().catch(() => []),
      api.listDnsGroups().catch(() => []),
      api.getSettings().catch(() => null),
    ]);
    inbounds.value = ibs;
    certs.value = cs;
    outboundGroups.value = gs;
    dnsGroups.value = dgs;
    if (st?.effective_share_host) {
      currentShareHost.value = st.effective_share_host;
    } else if (ibs[0]?.share_host) {
      currentShareHost.value = ibs[0].share_host;
    }
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

onMounted(loadData);

function transportLabel(ib) {
  if (['hysteria2', 'tuic'].includes(ib.protocol) || ib.stream_settings?.network === 'quic') return 'QUIC';
  return (ib.stream_settings?.network || 'tcp').toUpperCase();
}

function securityLabel(ib) {
  if (['hysteria2', 'tuic'].includes(ib.protocol) || ib.stream_settings?.network === 'quic') return 'TLS';
  const s = ib.stream_settings?.security || 'none';
  return s === 'none' ? '' : s.toUpperCase();
}

function securityColor(ib) {
  const s = securityLabel(ib);
  if (s === 'REALITY') return 'gold';
  if (s === 'TLS') return 'green';
  if (s === 'SHADOWTLS') return 'magenta';
  return 'default';
}

function hasVlessNativeEnc(ib) {
  const dec = (ib.protocol_settings?.vless_decryption || '').trim();
  return ib.protocol === 'vless' && Boolean(dec) && dec.toLowerCase() !== 'none';
}

function hasMldsa65(ib) {
  return (
    ib.stream_settings?.security === 'reality' &&
    Boolean((ib.stream_settings?.reality?.mldsa65_seed || '').trim())
  );
}

function hasVision(ib) {
  if (ib.protocol !== 'vless' || ib.stream_settings?.network !== 'tcp') return false;
  if (hasVlessNativeEnc(ib)) {
    return Boolean(ib.protocol_settings?.vless_native_vision);
  }
  return (
    (ib.stream_settings?.security === 'reality' && ib.stream_settings?.reality?.vision) ||
    (ib.stream_settings?.security === 'tls' && ib.stream_settings?.tls?.vision)
  );
}

function hasH2Mux(ib) {
  if (!ib.stream_settings?.h2mux?.enabled || hasVision(ib)) return false;
  const p = ib.protocol;
  const net = ib.stream_settings?.network || 'tcp';
  const sec = ib.stream_settings?.security || 'none';
  if (sec === 'shadowtls') return false;
  if (['vless', 'vmess', 'trojan'].includes(p)) return ['tcp', 'ws'].includes(net);
  if (p === 'shadowsocks') return net === 'tcp' && sec === 'none';
  return false;
}

function quotaPct(ib) {
  if (!ib.total_quota_bytes) return 0;
  return Math.min(100, Math.round(((ib.up_bytes + ib.down_bytes) / ib.total_quota_bytes) * 100));
}

function formatDate(ms) {
  return dayjs(ms).format('YYYY-MM-DD HH:mm');
}

function formatCred(ib, c) {
  if (['vless', 'vmess'].includes(ib.protocol)) return c.uuid;
  if (ib.protocol === 'tuic') return `${c.uuid.slice(0, 8)}…:${c.password}`;
  if (['naiveproxy', 'socks', 'http', 'mixed'].includes(ib.protocol)) {
    return c.username ? `${c.username}:${c.password}` : '(no auth)';
  }
  return c.password;
}

async function copyCred(ib, c) {
  const raw = ['vless', 'vmess'].includes(ib.protocol) ? c.uuid : c.password || c.uuid;
  await copyText(raw);
  message.success(t('app.copied'));
}

function openCreate() {
  editingInbound.value = null;
  inboundModalOpen.value = true;
}

function openEdit(ib) {
  editingInbound.value = ib;
  inboundModalOpen.value = true;
}

function openShare(ib) {
  shareTitle.value = `${ib.remark} (:${ib.port})`;
  shareItems.value = ib.shares || [];
  shareModalOpen.value = true;
}

function openSingleClientShare(ib, idx) {
  shareTitle.value = `${ib.remark} - ${ib.clients[idx]?.name || ''}`;
  shareItems.value = ib.shares?.[idx] ? [ib.shares[idx]] : ib.shares || [];
  shareModalOpen.value = true;
}

function openAddClient(ib) {
  activeInboundForClient.value = ib;
  editingClient.value = null;
  clientModalOpen.value = true;
}

function openEditClient(ib, client) {
  activeInboundForClient.value = ib;
  editingClient.value = client;
  clientModalOpen.value = true;
}

async function handleDeleteClient(client) {
  try {
    await api.deleteClient(client.id);
    message.success(t('app.saveSuccess'));
    await loadData();
  } catch (e) {
    message.error(e.message);
  }
}

async function handleToggle(ib, val) {
  try {
    await api.toggleInbound(ib.id, val);
    ib.enable = val;
    message.success(t('app.saveSuccess'));
  } catch (e) {
    message.error(e.message);
  }
}

async function openCloneModal(ib) {
  cloneSourceId.value = ib.id;
  const { port } = await api.nextPort(ib.port + 1).catch(() => ({ port: ib.port + 1 }));
  cloneForm.port = port;
  cloneForm.remark = `${ib.remark}-${port}`;
  cloneForm.client_name = `client-${port}`;
  cloneForm.sub_id = ib.clients?.[0]?.sub_id || 'default';
  cloneModalOpen.value = true;
}

async function submitClone() {
  cloning.value = true;
  try {
    await api.cloneInbound(cloneSourceId.value, { ...cloneForm });
    message.success(t('app.saveSuccess'));
    cloneModalOpen.value = false;
    await loadData();
  } catch (e) {
    message.error(e.message);
  } finally {
    cloning.value = false;
  }
}

async function handleResetTraffic(ib) {
  try {
    await api.resetInboundTraffic(ib.id);
    message.success('OK');
    await loadData();
  } catch (e) {
    message.error(e.message);
  }
}

async function handleResetAll() {
  try {
    await api.resetAllTraffic();
    message.success('OK');
    await loadData();
  } catch (e) {
    message.error(e.message);
  }
}

function openHostModal() {
  editingPublicHost.value = currentShareHost.value === '127.0.0.1' ? '' : currentShareHost.value;
  hostModalOpen.value = true;
}

async function savePublicHost() {
  try {
    await api.setPublicHost(editingPublicHost.value.trim());
    hostModalOpen.value = false;
    message.success(t('app.saveSuccess'));
    await loadData();
  } catch (e) {
    message.error(e.message);
  }
}

function handleDelete(ib) {
  Modal.confirm({
    title: t('app.deleteConfirm'),
    content: `${ib.remark} (:${ib.port})`,
    okType: 'danger',
    onOk: async () => {
      await api.deleteInbound(ib.id);
      message.success('Deleted');
      await loadData();
    },
  });
}
</script>
