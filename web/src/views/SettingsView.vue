<template>
  <div style="display: flex; flex-direction: column; gap: 16px">
    <a-card :title="t('settings.panelSection')" size="small">
      <a-alert v-if="loadError" type="error" :message="loadError" show-icon>
        <template #action>
          <a-button size="small" @click="loadSettings">{{ t('app.refresh') }}</a-button>
        </template>
      </a-alert>
      <a-form layout="vertical" :disabled="!loaded || saving">
        <a-row :gutter="12">
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.listenIp')">
              <a-input v-model:value="form.panel_listen" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.listenPort')">
              <a-input-number v-model:value="form.panel_port" :min="1" :max="65535" style="width: 100%" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.basePath')">
              <a-input v-model:value="form.panel_base_path" placeholder="/ or /secret-panel" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.panelCert')">
              <a-input v-model:value="form.panel_cert_file" placeholder="/etc/shoes-panel/cert.pem" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.panelKey')">
              <a-input v-model:value="form.panel_key_file" placeholder="/etc/shoes-panel/key.pem" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-form-item :label="t('settings.sessionTtl')">
          <a-input-number v-model:value="form.session_ttl_hours" :min="1" :precision="0" />
        </a-form-item>

        <a-divider orientation="left">{{ t('settings.shareSection') }}</a-divider>
        <a-row :gutter="12">
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.publicHost')">
              <a-input v-model:value="form.public_host" placeholder="proxy.example.com or 203.0.113.10" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.subPublicUrl')">
              <a-input v-model:value="form.sub_public_url" placeholder="https://sub.example.com" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-divider orientation="left">{{ t('settings.shoesSection') }}</a-divider>
        <a-row :gutter="12">
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.shoesBin')">
              <a-input v-model:value="form.shoes_bin_path" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.shoesCfg')">
              <a-input v-model:value="form.shoes_config_path" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :xs="24" :md="8">
            <a-form-item :label="t('settings.clashAddr')">
              <a-input v-model:value="form.clash_api_addr" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="10">
            <a-form-item :label="t('settings.clashSecret')">
              <a-input-password v-model:value="form.clash_api_secret" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.autoStart')">
              <a-switch v-model:checked="form.shoes_auto_start" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-form-item :label="t('settings.extraYaml')">
          <a-textarea
            v-model:value="form.shoes_extra_yaml"
            :rows="4"
            style="font-family: monospace; font-size: 12px"
            placeholder="- global_settings:\n    reload_grace_secs: 300"
          />
        </a-form-item>

      </a-form>
      <a-space>
        <a-button type="primary" :disabled="!loaded" :loading="saving" @click="saveAllSettings">
          {{ t('app.save') }}
        </a-button>
        <a-button @click="downloadBackup">
          💾 {{ t('settings.backupDb') }}
        </a-button>
      </a-space>
    </a-card>

    <!-- Admin Credentials -->
    <a-card :title="t('settings.accountSection')" size="small">
      <a-form layout="vertical" :disabled="!loaded">
        <a-row :gutter="12">
          <a-col :xs="24" :md="8">
            <a-form-item :label="t('settings.currPwd')" required>
              <a-input-password v-model:value="pwdForm.current_password" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="8">
            <a-form-item :label="t('settings.newUser')" required>
              <a-input v-model:value="pwdForm.new_username" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="8">
            <a-form-item :label="t('settings.newPwd')" required>
              <a-input-password v-model:value="pwdForm.new_password" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-button danger :loading="updatingPwd" @click="handleUpdatePwd">
          {{ t('settings.updatePwdBtn') }}
        </a-button>
      </a-form>
    </a-card>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';

const emit = defineEmits(['loggedOut']);
const { t } = useI18n();
const loaded = ref(false);
const loadError = ref('');
const saving = ref(false);
const updatingPwd = ref(false);

const form = reactive({
  panel_listen: '0.0.0.0',
  panel_port: 54321,
  panel_base_path: '/',
  panel_cert_file: '',
  panel_key_file: '',
  public_host: '',
  sub_public_url: '',
  shoes_bin_path: '',
  shoes_config_path: '',
  clash_api_addr: '127.0.0.1:19090',
  clash_api_secret: '',
  shoes_auto_start: true,
  shoes_extra_yaml: '',
  session_ttl_hours: 168,
});

const pwdForm = reactive({
  current_password: '',
  new_username: 'admin',
  new_password: '',
});

async function loadSettings() {
  loaded.value = false;
  loadError.value = '';
  try {
    const res = await api.getSettings();
    Object.assign(form, res.settings);
    pwdForm.new_username = res.admin_username || 'admin';
    loaded.value = true;
  } catch (e) {
    loadError.value = e.message;
  }
}

onMounted(loadSettings);

async function saveAllSettings() {
  if (!loaded.value || saving.value) return;
  saving.value = true;
  try {
    const prevBase = window.__SHOES_BASE__ || '/';
    const saved = await api.saveSettings({ ...form });
    Object.assign(form, saved);
    message.success(t('app.saveSuccess'));
    if (saved.panel_base_path !== prevBase) {
      const target = saved.panel_base_path === '/' ? '/' : `${saved.panel_base_path}/`;
      window.location.href = target;
    }
  } catch (e) {
    message.error(e.message);
  } finally {
    saving.value = false;
  }
}

async function handleUpdatePwd() {
  updatingPwd.value = true;
  try {
    await api.changePassword({ ...pwdForm });
    message.success('Credentials updated. Please sign in again.');
    localStorage.removeItem('shoes_panel_token');
    emit('loggedOut');
  } catch (e) {
    message.error(e.message);
  } finally {
    updatingPwd.value = false;
  }
}

async function downloadBackup() {
  const token = localStorage.getItem('shoes_panel_token');
  const resp = await fetch(api.backupDbUrl(), {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!resp.ok) {
    message.error('Backup download failed');
    return;
  }
  const blob = await resp.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `shoes-panel-${new Date().toISOString().slice(0, 10)}.db`;
  a.click();
}
</script>
