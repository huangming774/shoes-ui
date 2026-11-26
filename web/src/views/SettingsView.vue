<template>
  <div style="display: flex; flex-direction: column; gap: 16px">
    <!-- 1. Panel Listener, SSL & Shoes Core Settings -->
    <a-card :title="t('settings.panelSection')" size="small">
      <a-alert v-if="loadError" type="error" :message="loadError" show-icon style="margin-bottom: 12px">
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

        <a-alert
          v-if="loaded"
          :type="listenerScheme === 'https' ? 'success' : 'warning'"
          show-icon
          :message="listenerScheme === 'https' ? t('settings.httpsActive') : t('settings.httpPlain')"
          style="margin-bottom: 14px"
        >
          <template v-if="listenerScheme !== 'https'" #action>
            <a-button size="small" type="primary" ghost @click="emit('navigate', 'certificates')">
              {{ t('settings.gotoCerts') }}
            </a-button>
          </template>
        </a-alert>

        <a-row :gutter="12">
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.panelCert')">
              <a-input v-model:value="form.panel_cert_file" placeholder="/etc/shoes-panel/certs/panel-ip-ssl.crt" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.panelKey')">
              <a-input v-model:value="form.panel_key_file" placeholder="/etc/shoes-panel/certs/panel-ip-ssl.key" />
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

      <a-space wrap>
        <a-button type="primary" :disabled="!loaded" :loading="saving" @click="saveAllSettings">
          {{ t('app.save') }}
        </a-button>
        <a-popconfirm :title="t('settings.restartPanelConfirm')" @confirm="handleRestartPanel">
          <a-button :loading="restartingPanel">
            🔄 {{ t('settings.restartPanel') }}
          </a-button>
        </a-popconfirm>
      </a-space>
    </a-card>

    <!-- 2. Online Version Check & One-Click Upgrade -->
    <a-card :title="t('settings.updateSection')" size="small">
      <template #extra>
        <a-button size="small" :loading="checkingUpdates" @click="loadUpdates(true)">
          🔍 {{ t('settings.checkUpdates') }}
        </a-button>
      </template>

      <a-row :gutter="[12, 12]">
        <a-col :xs="24" :md="12">
          <a-card size="small" title="Shoes Panel">
            <template #extra>
              <a-tag v-if="updates?.panel?.has_update" color="orange">{{ t('settings.updateAvailable') }}</a-tag>
              <a-tag v-else-if="updates?.panel && !updates.panel.error" color="green">{{ t('settings.upToDate') }}</a-tag>
            </template>
            <div style="font-size: 13px; display: flex; flex-direction: column; gap: 6px">
              <div>
                {{ t('settings.currentVer') }}: <code>v{{ updates?.panel?.current || '-' }}</code>
                <span style="margin: 0 8px; opacity: 0.4">|</span>
                {{ t('settings.latestVer') }}:
                <a v-if="updates?.panel?.release_url" :href="updates.panel.release_url" target="_blank" rel="noopener">
                  <code>{{ updates?.panel?.latest || '-' }}</code>
                </a>
                <code v-else>{{ updates?.panel?.latest || '-' }}</code>
              </div>
              <div v-if="updates?.panel?.error" style="color: #ff4d4f; font-size: 12px">
                {{ updates.panel.error }}
              </div>
              <div style="margin-top: 6px">
                <a-popconfirm :title="t('settings.upgradePanelConfirm')" @confirm="handleUpgradePanel">
                  <a-button
                    type="primary"
                    size="small"
                    :loading="upgradingPanel"
                    :disabled="updates?.panel && !updates.panel.download_supported && !updates.panel.error"
                  >
                    🚀 {{ t('settings.upgradePanelBtn') }}
                  </a-button>
                </a-popconfirm>
              </div>
            </div>
          </a-card>
        </a-col>

        <a-col :xs="24" :md="12">
          <a-card size="small" title="cfal/shoes Core">
            <template #extra>
              <a-tag v-if="updates?.shoes?.has_update" color="orange">{{ t('settings.updateAvailable') }}</a-tag>
              <a-tag v-else-if="updates?.shoes && !updates.shoes.error" color="green">{{ t('settings.upToDate') }}</a-tag>
            </template>
            <div style="font-size: 13px; display: flex; flex-direction: column; gap: 6px">
              <div>
                {{ t('settings.currentVer') }}: <code>{{ updates?.shoes?.current || '-' }}</code>
                <span style="margin: 0 8px; opacity: 0.4">|</span>
                {{ t('settings.latestVer') }}:
                <a v-if="updates?.shoes?.release_url" :href="updates.shoes.release_url" target="_blank" rel="noopener">
                  <code>{{ updates?.shoes?.latest || '-' }}</code>
                </a>
                <code v-else>{{ updates?.shoes?.latest || '-' }}</code>
              </div>
              <div v-if="updates?.shoes?.error" style="color: #ff4d4f; font-size: 12px">
                {{ updates.shoes.error }}
              </div>
              <div style="margin-top: 6px">
                <a-popconfirm :title="t('settings.upgradeShoesConfirm')" @confirm="handleUpgradeShoes">
                  <a-button
                    size="small"
                    :loading="upgradingShoes"
                    :disabled="updates?.shoes && !updates.shoes.download_supported && !updates.shoes.error"
                  >
                    ⚡ {{ t('settings.upgradeShoesBtn') }}
                  </a-button>
                </a-popconfirm>
              </div>
            </div>
          </a-card>
        </a-col>
      </a-row>
    </a-card>

    <!-- 3. Database Backup, Restore & Scheduled Local / Telegram Auto-Backup -->
    <a-card :title="t('settings.backupSection')" size="small">
      <a-form layout="vertical" :disabled="!loaded || saving">
        <a-row :gutter="12">
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.autoBackupEnable')">
              <a-switch v-model:checked="form.auto_backup_enabled" />
            </a-form-item>
          </a-col>
          <a-col :xs="12" :md="6">
            <a-form-item :label="t('settings.autoBackupInterval')">
              <a-input-number v-model:value="form.auto_backup_interval_hours" :min="1" :max="720" style="width: 100%" />
            </a-form-item>
          </a-col>
          <a-col :xs="12" :md="6">
            <a-form-item :label="t('settings.autoBackupRetain')">
              <a-input-number v-model:value="form.auto_backup_retain_count" :min="1" :max="100" style="width: 100%" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.tgBackupEnable')">
              <a-switch v-model:checked="form.tg_backup_enabled" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.tgBotToken')">
              <a-input-password v-model:value="form.tg_bot_token" placeholder="123456789:ABCdefGHIjklMNO..." />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12">
            <a-form-item :label="t('settings.tgChatId')">
              <a-input v-model:value="form.tg_chat_id" placeholder="123456789 (or comma separated IDs)" />
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>

      <a-space wrap style="margin-bottom: 14px">
        <a-button type="primary" :disabled="!loaded" :loading="saving" @click="saveAllSettings">
          {{ t('app.save') }}
        </a-button>
        <a-button :loading="backingUpNow" @click="handleBackupNow">
          💾 {{ t('settings.backupNowBtn') }}
        </a-button>
        <a-button @click="downloadBackup">
          ⬇ {{ t('settings.backupDb') }}
        </a-button>
        <a-button
          :loading="testingTg"
          :disabled="!form.tg_bot_token || !form.tg_chat_id"
          @click="handleTestTgBackup"
        >
          ✈️ {{ t('settings.backupTgTestBtn') }}
        </a-button>
        <a-button danger :loading="restoring" @click="triggerUploadRestore">
          📤 {{ t('settings.uploadRestoreBtn') }}
        </a-button>
        <input
          ref="restoreFileInput"
          type="file"
          accept=".db,.sqlite,.sqlite3"
          style="display: none"
          @change="onRestoreFileSelected"
        />
      </a-space>

      <a-table
        v-if="backups.length > 0"
        :data-source="backups"
        :columns="backupColumns"
        row-key="filename"
        size="small"
        :loading="loadingBackups"
        :pagination="false"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'filename'">
            <code>{{ record.filename }}</code>
          </template>
          <template v-else-if="column.key === 'size_bytes'">
            {{ formatBytes(record.size_bytes) }}
          </template>
          <template v-else-if="column.key === 'modified_at'">
            {{ formatTime(record.modified_at) }}
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-space size="small">
              <a-button size="small" @click="downloadLocalBackup(record.filename)">
                {{ t('settings.downloadBtn') }}
              </a-button>
              <a-popconfirm :title="t('settings.restoreConfirm')" @confirm="handleRestoreLocal(record.filename)">
                <a-button size="small" type="primary" ghost :loading="restoring">
                  {{ t('settings.restoreBtn') }}
                </a-button>
              </a-popconfirm>
              <a-popconfirm :title="t('app.deleteConfirm')" @confirm="handleDeleteBackup(record.filename)">
                <a-button size="small" danger>{{ t('app.delete') }}</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 4. Admin Credentials -->
    <a-card :title="t('settings.accountSection')" size="small">
      <a-form layout="vertical" :disabled="!loaded">
        <a-row :gutter="12">
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.currPwd')" required>
              <a-input-password v-model:value="pwdForm.current_password" autocomplete="current-password" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.newUser')" required>
              <a-input v-model:value="pwdForm.new_username" autocomplete="username" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.newPwd')">
              <a-input-password v-model:value="pwdForm.new_password" autocomplete="new-password" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="6">
            <a-form-item :label="t('settings.confirmPwd')">
              <a-input-password v-model:value="pwdForm.confirm_password" autocomplete="new-password" />
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
import { computed, onMounted, reactive, ref } from 'vue';
import { message, Modal } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';

const emit = defineEmits(['loggedOut', 'navigate']);
const { t } = useI18n();
const loaded = ref(false);
const loadError = ref('');
const saving = ref(false);
const updatingPwd = ref(false);
const restartingPanel = ref(false);
const listenerScheme = ref('http');

const updates = ref(null);
const checkingUpdates = ref(false);
const upgradingPanel = ref(false);
const upgradingShoes = ref(false);

const backups = ref([]);
const loadingBackups = ref(false);
const backingUpNow = ref(false);
const testingTg = ref(false);
const restoring = ref(false);
const restoreFileInput = ref(null);

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
  auto_backup_enabled: false,
  auto_backup_interval_hours: 24,
  auto_backup_retain_count: 7,
  tg_bot_token: '',
  tg_chat_id: '',
  tg_backup_enabled: false,
});

const pwdForm = reactive({
  current_password: '',
  new_username: 'admin',
  new_password: '',
  confirm_password: '',
});

const backupColumns = computed(() => [
  { title: t('settings.backupFile'), key: 'filename' },
  { title: t('settings.backupSize'), key: 'size_bytes', width: 110 },
  { title: t('settings.backupTime'), key: 'modified_at', width: 175 },
  { title: t('app.actions'), key: 'actions', width: 220 },
]);

function formatBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(2)} MB`;
}

function formatTime(unixSec) {
  if (!unixSec) return '-';
  return new Date(unixSec * 1000).toLocaleString();
}

async function loadSettings() {
  loaded.value = false;
  loadError.value = '';
  try {
    const res = await api.getSettings();
    Object.assign(form, res.settings);
    pwdForm.new_username = res.admin_username || 'admin';
    listenerScheme.value = res.listener_scheme || 'http';
    loaded.value = true;
  } catch (e) {
    loadError.value = e.message;
  }
}

async function loadBackups() {
  loadingBackups.value = true;
  try {
    backups.value = await api.listBackups();
  } catch {
    // non-fatal
  } finally {
    loadingBackups.value = false;
  }
}

async function loadUpdates(force = false) {
  checkingUpdates.value = true;
  try {
    updates.value = await api.checkUpdates(force);
  } catch (e) {
    message.error(e.message);
  } finally {
    checkingUpdates.value = false;
  }
}

onMounted(() => {
  loadSettings();
  loadBackups();
  loadUpdates(false);
});

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

function redirectAfterRestart(info) {
  const scheme = info?.target_scheme || window.location.protocol.replace(':', '');
  const port = info?.target_port || window.location.port;
  const bp = info?.target_base_path || window.__SHOES_BASE__ || '/';
  const suffix = bp === '/' ? '/' : `${bp.replace(/\/+$/, '')}/`;
  const host = window.location.hostname;
  const hostFmt = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  const targetUrl = `${scheme}://${hostFmt}:${port}${suffix}`;
  message.loading(t('settings.restartingPanel'), 4);
  setTimeout(() => {
    window.location.href = targetUrl;
  }, 3500);
}

async function handleRestartPanel() {
  restartingPanel.value = true;
  try {
    const res = await api.restartPanel();
    redirectAfterRestart(res);
  } catch (e) {
    message.error(e.message);
    restartingPanel.value = false;
  }
}

async function handleUpgradePanel() {
  upgradingPanel.value = true;
  try {
    const res = await api.upgradePanel();
    message.success(t('settings.upgradeSuccess', { name: 'Shoes Panel', ver: res.new_version }));
    redirectAfterRestart(null);
  } catch (e) {
    message.error(e.message);
    upgradingPanel.value = false;
  }
}

async function handleUpgradeShoes() {
  upgradingShoes.value = true;
  try {
    const res = await api.upgradeShoes();
    message.success(t('settings.upgradeSuccess', { name: 'Shoes Core', ver: res.new_version }));
    await loadUpdates(true);
  } catch (e) {
    message.error(e.message);
  } finally {
    upgradingShoes.value = false;
  }
}

async function handleBackupNow() {
  backingUpNow.value = true;
  try {
    const res = await api.backupNow(false);
    const extra = res.telegram_sent > 0 ? ` (+ Telegram x${res.telegram_sent})` : '';
    message.success(`${res.backup.filename}${extra}`);
    await loadBackups();
  } catch (e) {
    message.error(e.message);
  } finally {
    backingUpNow.value = false;
  }
}

async function handleTestTgBackup() {
  testingTg.value = true;
  try {
    const res = await api.backupTgTest({
      tg_bot_token: form.tg_bot_token,
      tg_chat_id: form.tg_chat_id,
    });
    message.success(`Telegram OK (${res.sent_chats} chat(s), ${res.filename})`);
  } catch (e) {
    message.error(e.message);
  } finally {
    testingTg.value = false;
  }
}

function triggerUploadRestore() {
  if (restoreFileInput.value) {
    restoreFileInput.value.value = '';
    restoreFileInput.value.click();
  }
}

function onRestoreFileSelected(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  Modal.confirm({
    title: t('settings.uploadRestoreBtn'),
    content: `${file.name} (${formatBytes(file.size)}) — ${t('settings.restoreConfirm')}`,
    okType: 'danger',
    onOk: async () => {
      restoring.value = true;
      try {
        const res = await api.restoreDb(file);
        message.success(t('settings.restoreSuccess', { pre: res.pre_restore_backup }));
        localStorage.removeItem('shoes_panel_token');
        emit('loggedOut');
      } catch (err) {
        message.error(err.message);
      } finally {
        restoring.value = false;
      }
    },
  });
}

async function handleRestoreLocal(filename) {
  restoring.value = true;
  try {
    const res = await api.restoreLocalBackup(filename);
    message.success(t('settings.restoreSuccess', { pre: res.pre_restore_backup }));
    localStorage.removeItem('shoes_panel_token');
    emit('loggedOut');
  } catch (e) {
    message.error(e.message);
  } finally {
    restoring.value = false;
  }
}

async function handleDeleteBackup(filename) {
  try {
    await api.deleteLocalBackup(filename);
    message.success('Deleted');
    await loadBackups();
  } catch (e) {
    message.error(e.message);
  }
}

async function fetchAuthDownload(url, downloadName) {
  const token = localStorage.getItem('shoes_panel_token');
  const resp = await fetch(url, {
    credentials: 'same-origin',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!resp.ok) {
    message.error('Backup download failed');
    return;
  }
  const blob = await resp.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = downloadName;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

async function downloadBackup() {
  await fetchAuthDownload(api.backupDbUrl(), `shoes-panel-${new Date().toISOString().slice(0, 10)}.db`);
}

async function downloadLocalBackup(filename) {
  await fetchAuthDownload(api.downloadLocalBackupUrl(filename), filename);
}

async function handleUpdatePwd() {
  if (pwdForm.new_password) {
    if (pwdForm.new_password.length < 4) {
      message.error(t('settings.pwdTooShort'));
      return;
    }
    if (pwdForm.new_password !== pwdForm.confirm_password) {
      message.error(t('settings.pwdMismatch'));
      return;
    }
  }
  updatingPwd.value = true;
  try {
    await api.changePassword({
      current_password: pwdForm.current_password,
      new_username: pwdForm.new_username,
      new_password: pwdForm.new_password,
    });
    message.success(t('settings.pwdUpdated'));
    localStorage.removeItem('shoes_panel_token');
    emit('loggedOut');
  } catch (e) {
    message.error(e.message);
  } finally {
    updatingPwd.value = false;
  }
}
</script>
