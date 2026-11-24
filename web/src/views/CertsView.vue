<template>
  <div>
    <a-card size="small" style="margin-bottom: 14px">
      <a-space wrap>
        <a-button type="primary" @click="openMode('acme')">+ {{ t('certs.addAcme') }}</a-button>
        <a-button @click="openMode('upload')">📋 {{ t('certs.uploadPem') }}</a-button>
        <a-button @click="openMode('selfsigned')">⚡ {{ t('certs.genSelfSigned') }}</a-button>
        <a-button @click="openMode('files')">📁 {{ t('certs.addFileRef') }}</a-button>
        <a-button @click="loadCerts">↻ {{ t('app.refresh') }}</a-button>
      </a-space>
    </a-card>

    <a-card size="small" :body-style="{ padding: 0 }">
      <a-table :data-source="certs" :columns="columns" row-key="id" :loading="loading" :pagination="false">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'name'">
            <code style="font-weight: 600">{{ record.name }}</code>
          </template>
          <template v-else-if="column.key === 'cert_type'">
            <a-tag :color="record.cert_type === 'acme' ? 'green' : 'blue'">
              {{ record.cert_type.toUpperCase() }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'detail'">
            <div v-if="record.cert_type === 'acme'" style="font-size: 12px">
              <div><b>Domains:</b> {{ (record.domains || []).join(', ') }}</div>
              <div style="opacity: 0.7">Challenge: {{ record.challenge_type }} · {{ record.email }}</div>
            </div>
            <div v-else style="font-size: 12px">
              <div><code>{{ record.cert_file }}</code></div>
              <div style="opacity: 0.7"><code>{{ record.key_file }}</code></div>
            </div>
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-space>
              <a-button v-if="record.cert_type === 'acme' || record.cert_file" size="small" @click="openEdit(record)">
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
      :title="t('certs.title')"
      width="640px"
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
          <a-form-item :label="t('certs.domains')" required>
            <a-input v-model:value="domainsStr" placeholder="proxy.example.com, 127.0.0.1" />
          </a-form-item>
        </template>

        <template v-else-if="mode === 'upload'">
          <a-form-item :label="t('certs.certPem')" required>
            <a-textarea v-model:value="uploadForm.cert_pem" :rows="5" style="font-family: monospace; font-size: 12px" placeholder="-----BEGIN CERTIFICATE-----..." />
          </a-form-item>
          <a-form-item :label="t('certs.keyPem')" required>
            <a-textarea v-model:value="uploadForm.key_pem" :rows="5" style="font-family: monospace; font-size: 12px" placeholder="-----BEGIN PRIVATE KEY-----..." />
          </a-form-item>
        </template>

        <template v-else-if="mode === 'acme'">
          <a-form-item :label="t('certs.domains')" required>
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
                  <a-select-option value="http01">HTTP-01</a-select-option>
                  <a-select-option value="tls_alpn01">TLS-ALPN-01</a-select-option>
                </a-select>
              </a-form-item>
            </a-col>
          </a-row>
          <a-form-item v-if="form.challenge_type === 'http01'" :label="t('certs.http01Listen')">
            <a-input v-model:value="form.http01_listen" placeholder="0.0.0.0:80" />
          </a-form-item>
          <a-form-item :label="t('certs.acmeDir')">
            <a-select v-model:value="form.directory_url">
              <a-select-option value="https://acme-v02.api.letsencrypt.org/directory">
                Let's Encrypt Production
              </a-select-option>
              <a-select-option value="https://acme-staging-v02.api.letsencrypt.org/directory">
                Let's Encrypt Staging (Testing)
              </a-select-option>
            </a-select>
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
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';

const { t } = useI18n();
const loading = ref(false);
const saving = ref(false);
const certs = ref([]);

const modalOpen = ref(false);
const mode = ref('acme');
const domainsStr = ref('');
const uploadForm = reactive({ cert_pem: '', key_pem: '' });
const form = reactive({
  id: 0,
  name: '',
  cert_type: 'files',
  cert_file: '',
  key_file: '',
  domains: [],
  email: '',
  directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
  terms_of_service: 'https://letsencrypt.org/documents/LE-SA-v1.4-April-3-2024.pdf',
  challenge_type: 'http01',
  http01_listen: '0.0.0.0:80',
  remark: '',
});

const columns = computed(() => [
  { title: t('certs.sourceName'), key: 'name', width: 160 },
  { title: t('certs.type'), key: 'cert_type', width: 100 },
  { title: 'Details / Paths', key: 'detail' },
  { title: t('app.remark'), dataIndex: 'remark', key: 'remark', width: 180 },
  { title: t('app.actions'), key: 'actions', width: 160 },
]);

async function loadCerts() {
  loading.value = true;
  try {
    certs.value = await api.listCerts();
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}

onMounted(loadCerts);

function openMode(m) {
  mode.value = m;
  Object.assign(form, {
    id: 0,
    name: m === 'selfsigned' ? `self-${Date.now().toString().slice(-4)}` : 'public-cert',
    cert_type: m === 'acme' ? 'acme' : 'files',
    cert_file: '',
    key_file: '',
    domains: [],
    email: '',
    directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
    terms_of_service: 'https://letsencrypt.org/documents/LE-SA-v1.4-April-3-2024.pdf',
    challenge_type: 'http01',
    http01_listen: '0.0.0.0:80',
    remark: '',
  });
  domainsStr.value = m === 'selfsigned' ? 'localhost, 127.0.0.1' : '';
  uploadForm.cert_pem = '';
  uploadForm.key_pem = '';
  modalOpen.value = true;
}

function openEdit(rec) {
  mode.value = rec.cert_type === 'acme' ? 'acme' : 'files';
  Object.assign(form, JSON.parse(JSON.stringify(rec)));
  domainsStr.value = (rec.domains || []).join(', ');
  modalOpen.value = true;
}

async function handleSave() {
  saving.value = true;
  try {
    const domains = domainsStr.value
      .split(',')
      .map((d) => d.trim())
      .filter(Boolean);

    if (mode.value === 'selfsigned') {
      await api.selfSignedCert({ name: form.name, domains, remark: form.remark });
    } else if (mode.value === 'upload') {
      await api.uploadCert({
        id: form.id,
        name: form.name,
        cert_pem: uploadForm.cert_pem,
        key_pem: uploadForm.key_pem,
        remark: form.remark,
      });
    } else {
      await api.saveCert({ ...form, domains });
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
