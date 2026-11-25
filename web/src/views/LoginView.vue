<template>
  <div class="login-bg">
    <div class="login-topbar">
      <a-space>
        <a-button @click="emit('toggleTheme')">
          <template #icon><BulbFilled v-if="isDark" /><BulbOutlined v-else /></template>
          {{ t(isDark ? 'app.themeLight' : 'app.themeDark') }}
        </a-button>
        <a-radio-group :value="locale" class="panel-language" aria-label="Language / 语言" @change="(e) => setLocale(e.target.value)">
          <a-radio-button value="zh">中文</a-radio-button>
          <a-radio-button value="en">EN</a-radio-button>
        </a-radio-group>
      </a-space>
    </div>

    <a-card class="login-card">
      <header class="login-heading">
        <span class="panel-brand__mark" aria-hidden="true"><ThunderboltFilled /></span>
        <h1>{{ t('app.loginTitle') }}</h1>
        <p>{{ t('app.subtitle') }}</p>
      </header>

      <a-form layout="vertical" @submit="onSubmit">
        <a-form-item :label="t('app.username')" html-for="panel-login-username">
          <a-input id="panel-login-username" v-model:value="username" size="large" autocomplete="username" />
        </a-form-item>
        <a-form-item :label="t('app.password')" html-for="panel-login-password">
          <a-input-password id="panel-login-password" v-model:value="password" size="large" autocomplete="current-password" />
        </a-form-item>
        <a-button
          type="primary"
          size="large"
          block
          :loading="loading"
          html-type="submit"
          class="login-submit"
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
import { BulbFilled, BulbOutlined, ThunderboltFilled } from '@ant-design/icons-vue';
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
  if (loading.value || !username.value || !password.value) return;
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
  min-block-size: 100dvh;
  display: grid;
  grid-template-rows: auto 1fr;
  padding: var(--panel-gutter);
  gap: var(--panel-space-6);
  background: radial-gradient(52rem 38rem at 48% 20%, var(--panel-glow), transparent 80%);
}
.login-topbar {
  justify-self: end;
}
.login-card {
  place-self: center;
  inline-size: min(100%, 26rem);
  border-radius: var(--panel-radius);
  box-shadow: var(--panel-lift);
  animation: panel-enter var(--panel-motion-view) var(--panel-ease) backwards;
}

.login-card :deep(.ant-card-body) {
  padding: clamp(var(--panel-space-4), 5vw, var(--panel-space-8));
}

.login-heading {
  margin-block-end: var(--panel-space-6);
}

.login-heading h1 {
  margin: var(--panel-space-3) 0 0.25rem;
  font-size: clamp(1.375rem, 3vw, 1.75rem);
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1.25;
}

.login-heading p {
  margin: 0;
  color: var(--panel-muted);
  line-height: 1.5;
}

.login-submit {
  min-block-size: 2.75rem;
  font-weight: 650;
}
</style>
