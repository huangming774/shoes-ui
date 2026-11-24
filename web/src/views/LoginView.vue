<template>
  <div class="login-bg">
    <div class="login-topbar">
      <a-space>
        <a-button size="small" @click="emit('toggleTheme')">
          {{ isDark ? '☀️ ' + t('app.themeLight') : '🌙 ' + t('app.themeDark') }}
        </a-button>
        <a-radio-group :value="locale" size="small" button-style="solid" @change="(e) => setLocale(e.target.value)">
          <a-radio-button value="zh">中文</a-radio-button>
          <a-radio-button value="en">EN</a-radio-button>
        </a-radio-group>
      </a-space>
    </div>

    <a-card class="login-card" :bordered="false">
      <div style="text-align: center; margin-bottom: 24px">
        <div class="brand-badge">⚡ SHOES PANEL</div>
        <h2 style="margin: 10px 0 4px; font-weight: 700">{{ t('app.loginTitle') }}</h2>
        <div style="opacity: 0.65; font-size: 13px">{{ t('app.subtitle') }}</div>
      </div>

      <a-form layout="vertical" @submit.prevent="onSubmit">
        <a-form-item :label="t('app.username')">
          <a-input v-model:value="username" size="large" autocomplete="username" @pressEnter="onSubmit" />
        </a-form-item>
        <a-form-item :label="t('app.password')">
          <a-input-password v-model:value="password" size="large" autocomplete="current-password" @pressEnter="onSubmit" />
        </a-form-item>
        <a-button
          type="primary"
          size="large"
          block
          :loading="loading"
          style="margin-top: 8px; height: 42px; font-weight: 600"
          @click="onSubmit"
        >
          {{ t('app.loginBtn') }}
        </a-button>
      </a-form>
    </a-card>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { setLocale } from '../i18n';

defineProps({ isDark: Boolean });
const emit = defineEmits(['loggedIn', 'toggleTheme']);
const { t, locale } = useI18n();

const username = ref('admin');
const password = ref('');
const loading = ref(false);

async function onSubmit() {
  if (!username.value || !password.value) return;
  loading.value = true;
  try {
    const res = await api.login(username.value, password.value);
    if (res?.token) {
      localStorage.setItem('shoes_panel_token', res.token);
    }
    message.success(t('app.loginSuccess'));
    emit('loggedIn', res.username);
  } catch (e) {
    message.error(e.message);
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
.login-bg {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  position: relative;
  background: radial-gradient(circle at 20% 20%, rgba(22, 119, 255, 0.16), transparent 45%),
    radial-gradient(circle at 80% 80%, rgba(114, 46, 209, 0.16), transparent 45%);
}
.login-topbar {
  position: absolute;
  top: 20px;
  right: 24px;
}
.login-card {
  width: 100%;
  max-width: 400px;
  border-radius: 16px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.16);
}
.brand-badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.8px;
  color: #1677ff;
  background: rgba(22, 119, 255, 0.12);
}
</style>
