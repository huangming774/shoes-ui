<template>
  <div>
    <a-card size="small" style="margin-bottom: 14px">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px">
        <a-space>
          <a-button type="primary" @click="openCreate">+ {{ t('subs.add') }}</a-button>
          <a-button @click="loadSubs">↻ {{ t('app.refresh') }}</a-button>
        </a-space>
        <span style="font-size: 12px; opacity: 0.72">{{ t('subs.subIdTip') }}</span>
      </div>
    </a-card>

    <a-card size="small" :body-style="{ padding: 0 }">
      <a-table :data-source="subs" :columns="columns" row-key="id" :loading="loading" :pagination="false">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'enable'">
            <a-badge :status="record.enable ? 'success' : 'default'" :text="record.enable ? 'ON' : 'OFF'" />
          </template>
          <template v-else-if="column.key === 'sub_id'">
            <a-tag color="geekblue">{{ record.sub_id }}</a-tag>
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

    <!-- Create/Edit Modal -->
    <a-modal v-model:open="modalOpen" :title="t('subs.title')" @ok="handleSave">
      <a-form layout="vertical">
        <a-form-item :label="t('subs.name')" required>
          <a-input v-model:value="form.name" placeholder="VIP Subscription" />
        </a-form-item>
        <a-form-item :label="t('subs.subId')" :extra="t('subs.subIdTip')" required>
          <a-input v-model:value="form.sub_id" placeholder="default or all or alice" />
        </a-form-item>
        <a-form-item :label="t('app.enable')">
          <a-switch v-model:checked="form.enable" />
        </a-form-item>
      </a-form>
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
const form = reactive({ id: 0, name: '', sub_id: 'all', token: '', enable: true });

const qrOpen = ref(false);
const qrTitle = ref('');
const qrItems = ref([]);

const columns = computed(() => [
  { title: t('app.status'), key: 'enable', width: 85 },
  { title: t('subs.name'), dataIndex: 'name', key: 'name', width: 180 },
  { title: 'subId', key: 'sub_id', width: 120 },
  { title: t('subs.nodeCount'), key: 'node_count', width: 95 },
  { title: 'Subscription URLs', key: 'links' },
  { title: t('app.actions'), key: 'actions', width: 250 },
]);

async function loadSubs() {
  loading.value = true;
  try {
    subs.value = await api.listSubscriptions();
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

onMounted(loadSubs);

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
  Object.assign(form, { id: 0, name: 'All Nodes', sub_id: 'all', token: '', enable: true });
  modalOpen.value = true;
}

function openEdit(rec) {
  Object.assign(form, rec);
  modalOpen.value = true;
}

async function handleSave() {
  try {
    await api.saveSubscription({ ...form });
    message.success(t('app.saveSuccess'));
    modalOpen.value = false;
    await loadSubs();
  } catch (e) {
    message.error(e.message);
  }
}

async function handleRotate(rec) {
  try {
    await api.rotateSubscription(rec.id);
    message.success(t('app.saveSuccess'));
    await loadSubs();
  } catch (e) {
    message.error(e.message);
  }
}

async function handleDelete(rec) {
  try {
    await api.deleteSubscription(rec.id);
    await loadSubs();
  } catch (e) {
    message.error(e.message);
  }
}
</script>
