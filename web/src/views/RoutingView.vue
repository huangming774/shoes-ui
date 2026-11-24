<template>
  <a-card size="small">
    <a-tabs v-model:activeKey="activeTab" @change="onTabChange">
      <!-- Tab 1: Outbound Groups + Live Clash Selector -->
      <a-tab-pane key="outbounds" :tab="t('routing.outboundsTab')">
        <div style="display: flex; justify-content: space-between; margin-bottom: 12px">
          <a-space>
            <a-button type="primary" @click="openNewGroup">+ {{ t('routing.addGroup') }}</a-button>
            <a-button @click="loadAll">↻ {{ t('app.refresh') }}</a-button>
          </a-space>
        </div>

        <a-table :data-source="groups" :columns="groupColumns" row-key="id" size="small" :pagination="false">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'enable'">
              <a-badge :status="record.enable ? 'success' : 'default'" :text="record.enable ? 'ON' : 'OFF'" />
            </template>
            <template v-else-if="column.key === 'group_type'">
              <a-tag color="purple">{{ record.group_type }}</a-tag>
            </template>
            <template v-else-if="column.key === 'members'">
              <span v-if="record.raw_chains_yaml">Custom YAML</span>
              <a-space v-else wrap :size="4">
                <a-tag v-for="(m, i) in record.members" :key="i">
                  {{ m.name }} ({{ m.protocol }})
                </a-tag>
              </a-space>
            </template>
            <template v-else-if="column.key === 'actions'">
              <a-space>
                <a-button size="small" @click="openEditGroup(record)">{{ t('app.edit') }}</a-button>
                <a-popconfirm :title="t('app.deleteConfirm')" @confirm="delGroup(record)">
                  <a-button size="small" danger>{{ t('app.delete') }}</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>

        <!-- Live Clash Controller Selector Box -->
        <a-divider orientation="left" style="margin-top: 22px">{{ t('routing.liveSelector') }}</a-divider>
        <div v-if="liveGroups.length === 0" style="opacity: 0.65; font-size: 13px; padding: 8px 0">
          No active Selector / URL-Test groups reported by shoes Clash API yet.
        </div>
        <a-row v-else :gutter="[12, 12]">
          <a-col v-for="lg in liveGroups" :key="lg.name" :xs="24" :md="12">
            <a-card size="small" :title="`${lg.name} (${lg.type})`">
              <template #extra>
                <a-button size="small" :loading="probing === lg.name" @click="probeGroup(lg.name)">
                  ⚡ {{ t('routing.probeDelay') }}
                </a-button>
              </template>
              <a-space wrap>
                <a-tag
                  v-for="m in lg.all || []"
                  :key="m"
                  :color="lg.now === m ? 'blue' : 'default'"
                  style="cursor: pointer; padding: 4px 10px"
                  @click="lg.type === 'Selector' && selectMember(lg.name, m)"
                >
                  {{ lg.now === m ? '● ' : '' }}{{ m }}
                  <span v-if="delays[m]" style="opacity: 0.75"> ({{ delays[m] }}ms)</span>
                </a-tag>
              </a-space>
            </a-card>
          </a-col>
        </a-row>
      </a-tab-pane>

      <!-- Tab 2: Routing Rules -->
      <a-tab-pane key="rules" :tab="t('routing.rulesTab')">
        <div style="margin-bottom: 12px">
          <a-space>
            <a-button type="primary" @click="openNewRule">+ {{ t('routing.addRule') }}</a-button>
            <a-button @click="loadAll">↻ {{ t('app.refresh') }}</a-button>
          </a-space>
        </div>

        <a-table :data-source="rules" :columns="ruleColumns" row-key="id" size="small" :pagination="false">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'enable'">
              <a-badge :status="record.enable ? 'success' : 'default'" :text="record.enable ? 'ON' : 'OFF'" />
            </template>
            <template v-else-if="column.key === 'action'">
              <a-tag :color="record.action === 'block' ? 'error' : 'success'">
                {{ record.action.toUpperCase() }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'outbound'">
              <a-tag color="geekblue">{{ record.action === 'block' ? '-' : record.outbound }}</a-tag>
            </template>
            <template v-else-if="column.key === 'actions'">
              <a-space>
                <a-button size="small" @click="openEditRule(record)">{{ t('app.edit') }}</a-button>
                <a-popconfirm :title="t('app.deleteConfirm')" @confirm="delRule(record)">
                  <a-button size="small" danger>{{ t('app.delete') }}</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- Tab 3: Full YAML Preview -->
      <a-tab-pane key="yaml" :tab="t('routing.yamlTab')">
        <div style="display: flex; justify-content: space-between; margin-bottom: 10px">
          <code>{{ previewPath }}</code>
          <a-space>
            <a-button size="small" @click="copyYaml">Copy YAML</a-button>
            <a-button size="small" type="primary" @click="triggerReload">⚡ {{ t('dashboard.reload') }}</a-button>
          </a-space>
        </div>
        <pre
          style="max-height: 65vh; overflow: auto; padding: 14px; border-radius: 8px; background: rgba(127,127,127,0.12); font-size: 12px"
        >{{ previewYaml }}</pre>
      </a-tab-pane>
    </a-tabs>

    <!-- Outbound Group Modal -->
    <a-modal v-model:open="groupModalOpen" :title="t('routing.addGroup')" width="740px" @ok="saveGroup">
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :span="9">
            <a-form-item :label="t('routing.groupName')" required>
              <a-input v-model:value="groupForm.name" placeholder="proxy-out" />
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item :label="t('routing.groupType')">
              <a-select v-model:value="groupForm.group_type">
                <a-select-option value="selector">selector (手动选择)</a-select-option>
                <a-select-option value="url-test">url-test (自动测速)</a-select-option>
                <a-select-option value="round-robin">round-robin (轮询)</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="7">
            <a-form-item :label="t('app.enable')">
              <a-switch v-model:checked="groupForm.enable" />
            </a-form-item>
          </a-col>
        </a-row>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px">
          <b>{{ t('routing.members') }}</b>
          <a-button size="small" type="dashed" @click="addMemberRow">+ {{ t('routing.addMember') }}</a-button>
        </div>

        <div
          v-for="(m, idx) in groupForm.members"
          :key="idx"
          style="padding: 10px; margin-bottom: 8px; border-radius: 8px; border: 1px solid rgba(127,127,127,0.2)"
        >
          <a-row :gutter="8">
            <a-col :span="5">
              <a-input v-model:value="m.name" placeholder="Node Name" size="small" />
            </a-col>
            <a-col :span="5">
              <a-select v-model:value="m.protocol" size="small" style="width: 100%">
                <a-select-option value="socks">SOCKS5</a-select-option>
                <a-select-option value="http">HTTP</a-select-option>
                <a-select-option value="shadowsocks">Shadowsocks</a-select-option>
                <a-select-option value="vless">VLESS</a-select-option>
                <a-select-option value="trojan">Trojan</a-select-option>
                <a-select-option value="direct">Direct</a-select-option>
              </a-select>
            </a-col>
            <a-col :span="7">
              <a-input v-if="m.protocol !== 'direct'" v-model:value="m.address" placeholder="host:port" size="small" />
            </a-col>
            <a-col :span="5">
              <a-input
                v-if="m.protocol === 'vless'"
                v-model:value="m.uuid"
                placeholder="UUID"
                size="small"
              />
              <a-input
                v-else-if="m.protocol !== 'direct'"
                v-model:value="m.password"
                placeholder="Password"
                size="small"
              />
            </a-col>
            <a-col :span="2" style="text-align: right">
              <a-button size="small" danger type="text" @click="groupForm.members.splice(idx, 1)">✕</a-button>
            </a-col>
          </a-row>
        </div>

        <a-form-item :label="t('routing.rawChainsYaml')" style="margin-top: 10px">
          <a-textarea v-model:value="groupForm.raw_chains_yaml" :rows="3" style="font-family: monospace; font-size: 12px" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- Routing Rule Modal -->
    <a-modal v-model:open="ruleModalOpen" :title="t('routing.addRule')" width="560px" @ok="saveRule">
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :span="14">
            <a-form-item :label="t('app.remark')">
              <a-input v-model:value="ruleForm.remark" placeholder="Block private IPs / Route OpenAI" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('routing.priority')">
              <a-input-number v-model:value="ruleForm.priority" style="width: 100%" />
            </a-form-item>
          </a-col>
          <a-col :span="4">
            <a-form-item :label="t('app.enable')">
              <a-switch v-model:checked="ruleForm.enable" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('routing.matchType')">
              <a-select v-model:value="ruleForm.match_type">
                <a-select-option value="masks">IP CIDR / Host Masks</a-select-option>
                <a-select-option value="domain">Domain Suffix</a-select-option>
                <a-select-option value="destination_port">Destination Port</a-select-option>
                <a-select-option value="udp_stun">UDP STUN / DTLS</a-select-option>
                <a-select-option value="any">Catch-All (Any Destination)</a-select-option>
                <a-select-option value="raw_yaml">Raw RuleConfig YAML</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('routing.action')">
              <a-select v-model:value="ruleForm.action">
                <a-select-option value="allow">Allow</a-select-option>
                <a-select-option value="block">Block</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col v-if="ruleForm.action === 'allow'" :span="6">
            <a-form-item :label="t('routing.outbound')">
              <a-select v-model:value="ruleForm.outbound">
                <a-select-option value="direct">direct</a-select-option>
                <a-select-option v-for="g in groups" :key="g.name" :value="g.name">{{ g.name }}</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>

        <a-form-item v-if="!['any', 'udp_stun'].includes(ruleForm.match_type)" :label="t('routing.matchValue')">
          <a-textarea
            v-model:value="ruleForm.match_value"
            :rows="4"
            placeholder="e.g. 10.0.0.0/8, 192.168.0.0/16 or openai.com, google.com"
          />
        </a-form-item>
      </a-form>
    </a-modal>
  </a-card>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { copyText } from '../utils';

const { t } = useI18n();
const activeTab = ref('outbounds');
const groups = ref([]);
const rules = ref([]);
const liveGroups = ref([]);
const delays = reactive({});
const probing = ref('');

const previewYaml = ref('');
const previewPath = ref('');

const groupModalOpen = ref(false);
const groupForm = reactive({
  id: 0,
  name: '',
  enable: true,
  group_type: 'selector',
  default_member: '',
  test_url: 'https://www.gstatic.com/generate_204',
  interval_secs: 300,
  timeout_ms: 5000,
  tolerance_ms: 50,
  members: [],
  raw_chains_yaml: '',
  remark: '',
});

const ruleModalOpen = ref(false);
const ruleForm = reactive({
  id: 0,
  priority: 100,
  enable: true,
  remark: '',
  match_type: 'masks',
  match_value: '',
  action: 'allow',
  outbound: 'direct',
});

const groupColumns = computed(() => [
  { title: t('app.status'), key: 'enable', width: 80 },
  { title: t('routing.groupName'), dataIndex: 'name', key: 'name', width: 160 },
  { title: t('routing.groupType'), key: 'group_type', width: 130 },
  { title: t('routing.members'), key: 'members' },
  { title: t('app.actions'), key: 'actions', width: 160 },
]);

const ruleColumns = computed(() => [
  { title: '#', dataIndex: 'priority', key: 'priority', width: 70 },
  { title: t('app.status'), key: 'enable', width: 80 },
  { title: t('app.remark'), dataIndex: 'remark', key: 'remark', width: 180 },
  { title: t('routing.matchType'), dataIndex: 'match_type', key: 'match_type', width: 140 },
  { title: t('routing.matchValue'), dataIndex: 'match_value', key: 'match_value', ellipsis: true },
  { title: t('routing.action'), key: 'action', width: 95 },
  { title: t('routing.outbound'), key: 'outbound', width: 130 },
  { title: t('app.actions'), key: 'actions', width: 150 },
]);

async function loadAll() {
  const [gs, rs, cp] = await Promise.all([
    api.listOutboundGroups().catch(() => []),
    api.listRoutingRules().catch(() => []),
    api.clashProxies().catch(() => ({ proxies: {} })),
  ]);
  groups.value = gs;
  rules.value = rs;
  const map = cp?.proxies || {};
  liveGroups.value = Object.values(map).filter((p) => ['Selector', 'URLTest', 'LoadBalance'].includes(p.type));
}

onMounted(loadAll);

async function onTabChange(k) {
  if (k === 'yaml') {
    const res = await api.shoesConfigPreview().catch(() => ({ yaml: '', path: '' }));
    previewYaml.value = res.yaml;
    previewPath.value = res.path;
  }
}

function addMemberRow() {
  groupForm.members.push({
    name: `node-${groupForm.members.length + 1}`,
    protocol: 'socks',
    address: '127.0.0.1:1080',
    uuid: '',
    username: '',
    password: '',
    cipher: 'aes-256-gcm',
    tls: false,
    sni: '',
    verify: true,
  });
}

function openNewGroup() {
  Object.assign(groupForm, {
    id: 0,
    name: 'upstream-pool',
    enable: true,
    group_type: 'selector',
    default_member: '',
    test_url: 'https://www.gstatic.com/generate_204',
    interval_secs: 300,
    timeout_ms: 5000,
    tolerance_ms: 50,
    members: [],
    raw_chains_yaml: '',
    remark: '',
  });
  addMemberRow();
  groupModalOpen.value = true;
}

function openEditGroup(rec) {
  Object.assign(groupForm, JSON.parse(JSON.stringify(rec)));
  groupModalOpen.value = true;
}

async function saveGroup() {
  try {
    await api.saveOutboundGroup(JSON.parse(JSON.stringify(groupForm)));
    message.success(t('app.saveSuccess'));
    groupModalOpen.value = false;
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function delGroup(rec) {
  try {
    await api.deleteOutboundGroup(rec.id);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function selectMember(groupName, member) {
  try {
    await api.clashSelectProxy(groupName, member);
    message.success(`${groupName} → ${member}`);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function probeGroup(groupName) {
  probing.value = groupName;
  try {
    const res = await api.clashDelay('group', groupName);
    Object.assign(delays, res || {});
  } catch (e) {
    message.error(e.message);
  } finally {
    probing.value = '';
  }
}

function openNewRule() {
  Object.assign(ruleForm, {
    id: 0,
    priority: 100,
    enable: true,
    remark: 'Block Private LAN',
    match_type: 'masks',
    match_value: '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
    action: 'block',
    outbound: 'direct',
  });
  ruleModalOpen.value = true;
}

function openEditRule(rec) {
  Object.assign(ruleForm, JSON.parse(JSON.stringify(rec)));
  ruleModalOpen.value = true;
}

async function saveRule() {
  try {
    await api.saveRoutingRule({ ...ruleForm });
    message.success(t('app.saveSuccess'));
    ruleModalOpen.value = false;
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function delRule(rec) {
  try {
    await api.deleteRoutingRule(rec.id);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function copyYaml() {
  await copyText(previewYaml.value);
  message.success(t('app.copied'));
}

async function triggerReload() {
  try {
    const res = await api.shoesReload();
    previewYaml.value = res.yaml;
    message.success(t('app.saveSuccess'));
  } catch (e) {
    message.error(e.message);
  }
}
</script>
