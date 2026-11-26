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

    <main class="login-card">
      <section class="brand-art" aria-labelledby="login-brand">
        <div class="circuit" aria-hidden="true">
          <div class="chip-stack">
            <div class="chip chip-base"></div>
            <div class="chip chip-middle"></div>
            <div class="chip chip-top"><ThunderboltFilled /></div>
          </div>
        </div>
        <div class="brand-caption">
          <p id="login-brand" class="wordmark">Shoes<span>Panel</span></p>
          <p>{{ t('app.subtitle') }}</p>
        </div>
      </section>
      <div class="login-form">
      <header class="login-heading">
        <h1>{{ t('app.loginTitle') }}</h1>
      </header>

      <a-form layout="vertical" @submit="onSubmit">
        <a-form-item :label="t('app.username')" html-for="panel-login-username">
          <a-input id="panel-login-username" v-model:value="username" size="large" autocomplete="username">
            <template #prefix><UserOutlined aria-hidden="true" /></template>
          </a-input>
        </a-form-item>
        <a-form-item :label="t('app.password')" html-for="panel-login-password">
          <a-input-password id="panel-login-password" v-model:value="password" size="large" autocomplete="current-password">
            <template #prefix><LockOutlined aria-hidden="true" /></template>
          </a-input-password>
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
      </div>
    </main>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { message } from 'ant-design-vue';
import { BulbFilled, BulbOutlined, LockOutlined, ThunderboltFilled, UserOutlined } from '@ant-design/icons-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { setLocale } from '../i18n';

defineProps({ isDark: Boolean });
const emit = defineEmits(['loggedIn', 'toggleTheme']);
const { t, locale } = useI18n();

const username = ref('');
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
    emit('loggedIn', res);
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
  background-color: var(--panel-canvas);
  background-image: radial-gradient(ellipse at 30% 30%, var(--panel-glow), transparent 65%),
    radial-gradient(var(--panel-line) 1px, transparent 1px);
  background-size: auto, 20px 20px;
}
.login-topbar {
  justify-self: end;
}
.login-card {
  place-self: center;
  inline-size: min(100%, 59rem);
  display: grid;
  grid-template-columns: minmax(0, 1.05fr) minmax(0, 1fr);
  overflow: hidden;
  border: 1px solid var(--panel-line);
  border-radius: 1.5rem;
  background: var(--panel-surface);
  box-shadow: var(--panel-lift);
  animation: panel-enter var(--panel-motion-view) var(--panel-ease) backwards;
}

.brand-art {
  position: relative;
  isolation: isolate;
  overflow: hidden;
  min-height: 29rem;
  display: flex;
  align-items: flex-end;
  padding: clamp(1.5rem, 4vw, 3rem);
  color: #eaffff;
  background: radial-gradient(ellipse at 56% 35%, #145966 0%, #10333f 40%, #091e2b 78%);
}
.circuit {
  position: absolute;
  inset: 0;
  z-index: -1;
}
.circuit::before {
  content: '';
  position: absolute;
  inset: -70%;
  background-image: linear-gradient(#7cdddf26 1px, transparent 1px),
    linear-gradient(90deg, #7cdddf26 1px, transparent 1px),
    radial-gradient(circle at 1px 1px, #8acfcf99 1.4px, transparent 2px);
  background-size: 2.2rem 2.2rem;
  transform: rotateX(54deg) rotateZ(-38deg);
  mask-image: radial-gradient(ellipse, black 8%, transparent 62%);
}
.chip-stack {
  position: absolute;
  top: 39%;
  left: 50%;
  width: 10rem;
  aspect-ratio: 1;
  transform: translate(-50%, -50%);
}
.chip {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  border: 1px solid #76e6dd;
  border-radius: 18%;
  transform: translateY(var(--lift)) rotateX(52deg) rotateZ(-38deg);
}
.chip-base {
  --lift: 2.2rem;
  background: repeating-linear-gradient(90deg, #366975 0 2px, #163743 2px 8px);
  box-shadow: -3px 7px #091d29, 0 12px 32px #081a20;
}
.chip-middle {
  --lift: 0.9rem;
  background: linear-gradient(135deg, #8efae4aa, #207e8980 70%);
  box-shadow: 0 5px #215f68, 0 7px 20px #66ffe636;
}
.chip-top {
  --lift: -0.5rem;
  background: linear-gradient(140deg, #b0fff1, #62d8cd 26%, #398c96 65%, #284854);
  box-shadow: inset 0 0 0 6px #c6fff32e, inset 0 0 0 7px #eaffff55, 0 5px #326875;
}
.chip-top .anticon { font-size: 4rem; color: #eafffa; filter: drop-shadow(0 2px 3px #124c57); }
.brand-caption p { margin: 0; color: #b6d8dd; }
.brand-caption .wordmark { color: #f1fffd; font: 700 clamp(2.6rem, 5vw, 4rem)/1.1 var(--panel-font); letter-spacing: -.065em; margin-bottom: .55rem; }
.wordmark span { color: #86eee1; font-weight: 350; }
.login-form {
  align-self: center;
  padding: clamp(1.5rem, 4vw, 3rem);
}
.login-form :deep(.ant-input-affix-wrapper) { min-height: 2.85rem; border-radius: .65rem; }
.login-form :deep(.ant-input-prefix) { color: var(--panel-muted); margin-inline-end: .7rem; }
.login-form :deep(.ant-form-item-label label) { font-weight: 550; }
@media (max-width: 44rem) {
  .login-card { grid-template-columns: minmax(0, 1fr); max-width: 28rem; }
  .brand-art { min-height: 9rem; padding: 1.35rem; }
  .brand-caption { max-width: 64%; }
  .brand-caption .wordmark { font-size: 2.2rem; }
  .brand-caption p { font-size: .8rem; }
  .chip-stack { top: 43%; left: 81%; width: 4.8rem; }
  .chip-top .anticon { font-size: 2.3rem; }
  .chip-base { --lift: 1.1rem; }
  .chip-middle { --lift: .4rem; }
  .chip-top { --lift: -.25rem; }
}

.login-heading {
  margin-block-end: var(--panel-space-6);
}

.login-heading h1 {
  margin: 0;
  font-size: clamp(1.375rem, 3vw, 1.75rem);
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1.25;
}

.login-submit {
  min-block-size: 2.75rem;
  font-weight: 650;
  border-radius: .65rem;
}
</style>
