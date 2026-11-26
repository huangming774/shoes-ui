<template>
  <div>
    <!-- Subscription List Toolbar -->
    <a-card size="small" style="margin-bottom: 14px">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px">
        <a-space>
          <a-button type="primary" @click="openCreate">+ {{ t('subs.add') }}</a-button>
          <a-button @click="loadAll">↻ {{ t('app.refresh') }}</a-button>
        </a-space>
        <span style="font-size: 12px; opacity: 0.72">{{ t('subs.subIdTip') }}</span>
      </div>
    </a-card>

    <!-- Subscription List Table -->
    <a-card size="small" :body-style="{ padding: 0 }" style="margin-bottom: 16px">
      <a-table :data-source="subs" :columns="columns" row-key="id" :loading="loading" :pagination="false" :scroll="{ x: 960 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'enable'">
            <a-badge :status="record.enable ? 'success' : 'default'" :text="record.enable ? 'ON' : 'OFF'" />
          </template>
          <template v-else-if="column.key === 'sub_id'">
            <a-tag color="geekblue">{{ record.sub_id }}</a-tag>
          </template>
          <template v-else-if="column.key === 'template'">
            <a-tag :color="record.template ? 'cyan' : 'default'">
              {{ templateShortLabel(record.template) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'node_count'">
            <a-tag color="purple">{{ record.node_count || 0 }}</a-tag>
          </template>
          <template v-else-if="column.key === 'links'">
            <a-space wrap :size="6">
              <a-button size="small" type="primary" ghost @click="copyUrl(record.url_auto)">
                {{ t('subs.copyAuto') }}
              </a-button>
              <a-button size="small" @click="copyUrl(record.url_v2ray)">
                {{ t('subs.copyV2ray') }}
              </a-button>
              <a-button size="small" @click="copyUrl(record.url_clash)">
                {{ t('subs.copyClash') }}
              </a-button>
              <a-button size="small" @click="copyUrl(record.url_singbox)">
                {{ t('subs.copySingbox') }}
              </a-button>
              <a-button size="small" @click="showSubQr(record)">QR</a-button>
            </a-space>
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-space :size="6">
              <a-button size="small" @click="openEdit(record)">{{ t('app.edit') }}</a-button>
              <a-popconfirm :title="t('subs.rotateConfirm')" @confirm="handleRotate(record)">
                <a-button size="small">{{ t('subs.rotateToken') }}</a-button>
              </a-popconfirm>
              <a-popconfirm
                v-if="record.sub_id !== 'default'"
                :title="t('app.deleteConfirm')"
                @confirm="handleDelete(record)"
              >
                <a-button size="small" danger>{{ t('app.delete') }}</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- Clash / sing-box Subscription Rule Template Editor -->
    <a-card size="small" :title="`📋 ${t('subs.templateTitle')}`">
      <template #extra>
        <a-space>
          <a-button size="small" :loading="previewing" @click="openPreview">
            👁️ {{ t('subs.previewTemplate') }}
          </a-button>
          <a-button size="small" type="primary" :loading="savingTpl" @click="saveTemplate">
            💾 {{ t('subs.saveTemplate') }}
          </a-button>
        </a-space>
      </template>

      <a-alert
        type="info"
        show-icon
        :message="t('subs.templateUrlTip')"
        style="margin-bottom: 14px; font-size: 12px"
      />

      <a-form layout="vertical">
        <a-row :gutter="14">
          <a-col :xs="24" :lg="14">
            <a-form-item :label="t('subs.templateCol')">
              <a-select v-model:value="tplForm.preset" style="width: 100%">
                <a-select-option value="minimal">{{ t('subs.presetMinimal') }}</a-select-option>
                <a-select-option value="global_direct">{{ t('subs.presetGlobalDirect') }}</a-select-option>
                <a-select-option value="bypass_cn">{{ t('subs.presetBypassCn') }}</a-select-option>
                <a-select-option value="streaming">{{ t('subs.presetStreaming') }}</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :xs="24" :lg="10" style="display: flex; align-items: center; flex-wrap: wrap; gap: 14px; padding-top: 8px">
            <a-checkbox v-model:checked="tplForm.prepend_custom_rules">
              {{ t('subs.prependCustom') }}
            </a-checkbox>
            <a-checkbox v-model:checked="tplForm.enable_adblock">
              {{ t('subs.enableAdblock') }}
            </a-checkbox>
            <a-checkbox v-model:checked="tplForm.enable_ipv6">
              {{ t('subs.enableIpv6') }}
            </a-checkbox>
          </a-col>
        </a-row>

        <a-row :gutter="14">
          <a-col :xs="24" :lg="12">
            <a-form-item :label="t('subs.clashCustomRules')">
              <a-textarea
                v-model:value="tplForm.clash_custom_rules"
                :rows="6"
                style="font-family: monospace; font-size: 12px"
                placeholder="# Example:&#10;DOMAIN-SUFFIX,openai.com,🚀 Proxy&#10;DOMAIN-SUFFIX,corp.internal,DIRECT&#10;IP-CIDR,100.64.0.0/10,DIRECT,no-resolve"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :lg="12">
            <a-form-item :label="t('subs.singboxCustomRules')">
              <a-textarea
                v-model:value="tplForm.singbox_custom_rules"
                :rows="6"
                style="font-family: monospace; font-size: 12px"
                placeholder="# Clash-style lines OR sing-box JSON array:&#10;DOMAIN-SUFFIX,openai.com,proxy&#10;DOMAIN-SUFFIX,corp.internal,direct&#10;IP-CIDR,100.64.0.0/10,direct"
              />
            </a-form-item>
          </a-col>
        </a-row>

        <a-collapse ghost>
          <a-collapse-panel key="extra-groups" :header="t('subs.clashExtraGroups')">
            <a-textarea
              v-model:value="tplForm.clash_extra_groups_yaml"
              :rows="4"
              style="font-family: monospace; font-size: 12px"
              placeholder="- name: 🎮 Gaming&#10;  type: select&#10;  proxies:&#10;    - 🚀 Proxy&#10;    - DIRECT"
            />
          </a-collapse-panel>
        </a-collapse>
      </a-form>
    </a-card>

    <!-- Create/Edit Subscription Modal -->
    <a-modal v-model:open="modalOpen" :title="t('subs.title')" @ok="handleSave">
      <a-form layout="vertical">
        <a-form-item :label="t('subs.name')" required>
          <a-input v-model:value="form.name" placeholder="VIP Subscription" />
        </a-form-item>
        <a-form-item :label="t('subs.subId')" :extra="t('subs.subIdTip')" required>
          <a-input v-model:value="form.sub_id" placeholder="default or all or alice" />
        </a-form-item>
        <a-form-item :label="t('subs.templateCol')">
          <a-select v-model:value="form.template">
            <a-select-option value="">{{ t('subs.templateInherit') }}</a-select-option>
            <a-select-option value="minimal">{{ t('subs.presetShortMinimal') }}</a-select-option>
            <a-select-option value="global_direct">{{ t('subs.presetShortGlobalDirect') }}</a-select-option>
            <a-select-option value="bypass_cn">{{ t('subs.presetShortBypassCn') }}</a-select-option>
            <a-select-option value="streaming">{{ t('subs.presetShortStreaming') }}</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item :label="t('app.enable')">
          <a-switch v-model:checked="form.enable" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- Template Live Preview Modal -->
    <a-modal v-model:open="previewOpen" :title="t('subs.previewTitle')" width="860px" :footer="null">
      <a-tabs v-model:activeKey="previewTab">
        <a-tab-pane key="clash" tab="Clash / Mihomo YAML">
          <div style="margin-bottom: 8px; text-align: right">
            <a-button size="small" @click="copyUrl(previewData.clash_yaml)">{{ t('app.copy') }}</a-button>
          </div>
          <a-textarea
            :value="previewData.clash_yaml"
            :rows="18"
            readonly
            style="font-family: monospace; font-size: 12px"
          />
        </a-tab-pane>
        <a-tab-pane key="singbox" tab="sing-box JSON">
          <div style="margin-bottom: 8px; text-align: right">
            <a-button size="small" @click="copyUrl(previewData.singbox_json)">{{ t('app.copy') }}</a-button>
          </div>
          <a-textarea
            :value="previewData.singbox_json"
            :rows="18"
            readonly
            style="font-family: monospace; font-size: 12px"
          />
        </a-tab-pane>
      </a-tabs>
    </a-modal>

    <QrShareModal v-model:open="qrOpen" :title="qrTitle" :items="qrItems" />
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { copyText } from '../utils';
import QrShareModal from '../components/QrShareModal.vue';

const { t } = useI18n();
const loading = ref(false);
const subs = ref([]);

const modalOpen = ref(false);
const form = reactive({ id: 0, name: '', sub_id: 'all', token: '', enable: true, template: '' });

const savingTpl = ref(false);
const tplForm = reactive({
  preset: 'minimal',
  prepend_custom_rules: true,
  enable_adblock: false,
  enable_ipv6: false,
  clash_custom_rules: '',
  clash_extra_groups_yaml: '',
  singbox_custom_rules: '',
});

const previewOpen = ref(false);
const previewing = ref(false);
const previewTab = ref('clash');
const previewData = reactive({ clash_yaml: '', singbox_json: '' });

const qrOpen = ref(false);
const qrTitle = ref('');
const qrItems = ref([]);

const columns = computed(() => [
  { title: t('app.status'), key: 'enable', width: 80 },
  { title: t('subs.name'), dataIndex: 'name', key: 'name', width: 150 },
  { title: 'subId', key: 'sub_id', width: 100 },
  { title: t('subs.templateCol'), key: 'template', width: 125 },
  { title: t('subs.nodeCount'), key: 'node_count', width: 85 },
  { title: 'Subscription URLs', key: 'links' },
  { title: t('app.actions'), key: 'actions', width: 230 },
]);

function templateShortLabel(val) {
  switch ((val || '').toLowerCase()) {
    case 'minimal':
      return t('subs.presetShortMinimal');
    case 'global_direct':
      return t('subs.presetShortGlobalDirect');
    case 'bypass_cn':
      return t('subs.presetShortBypassCn');
    case 'streaming':
      return t('subs.presetShortStreaming');
    default:
      return t('subs.templateInherit');
  }
}

async function loadAll() {
  loading.value = true;
  try {
    const [list, tpl] = await Promise.all([
      api.listSubscriptions(),
      api.getSubTemplate().catch(() => null),
    ]);
    subs.value = list || [];
    if (tpl) {
      Object.assign(tplForm, {
        preset: tpl.preset || 'minimal',
        prepend_custom_rules: tpl.prepend_custom_rules !== false,
        enable_adblock: Boolean(tpl.enable_adblock),
        enable_ipv6: Boolean(tpl.enable_ipv6),
        clash_custom_rules: tpl.clash_custom_rules || '',
        clash_extra_groups_yaml: tpl.clash_extra_groups_yaml || '',
        singbox_custom_rules: tpl.singbox_custom_rules || '',
      });
    }
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

onMounted(loadAll);

async function saveTemplate() {
  savingTpl.value = true;
  try {
    const saved = await api.saveSubTemplate({ ...tplForm });
    Object.assign(tplForm, saved);
    message.success(t('subs.templateSaved'));
  } catch (e) {
    message.error(e.message);
  } finally {
    savingTpl.value = false;
  }
}

async function openPreview() {
  previewing.value = true;
  try {
    const res = await api.previewSubTemplate({
      sub_id: 'all',
      template: { ...tplForm },
    });
    previewData.clash_yaml = res.clash_yaml || '';
    previewData.singbox_json = res.singbox_json || '';
    previewOpen.value = true;
  } catch (e) {
    message.error(e.message);
  } finally {
    previewing.value = false;
  }
}

async function copyUrl(u) {
  await copyText(u);
  message.success(t('app.copied'));
}

function showSubQr(rec) {
  qrTitle.value = rec.name;
  qrItems.value = [
    { name: 'Auto (UA)', uri: rec.url_auto },
    { name: 'v2rayN', uri: rec.url_v2ray },
    { name: 'Clash / Mihomo', uri: rec.url_clash },
    { name: 'sing-box', uri: rec.url_singbox },
  ];
  qrOpen.value = true;
}

function openCreate() {
  Object.assign(form, { id: 0, name: 'All Nodes', sub_id: 'all', token: '', enable: true, template: '' });
  modalOpen.value = true;
}

function openEdit(rec) {
  Object.assign(form, { ...rec, template: rec.template || '' });
  modalOpen.value = true;
}

async function handleSave() {
  try {
    await api.saveSubscription({ ...form });
    message.success(t('app.saveSuccess'));
    modalOpen.value = false;
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function handleRotate(rec) {
  try {
    await api.rotateSubscription(rec.id);
    message.success(t('app.saveSuccess'));
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function handleDelete(rec) {
  try {
    await api.deleteSubscription(rec.id);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}
</script>
