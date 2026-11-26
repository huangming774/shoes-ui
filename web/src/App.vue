<template>
  <a-config-provider
    :locale="locale === 'zh' ? zhCN : enUS"
    :theme="panelTheme"
  >
    <div v-if="!ready" class="panel-startup" role="status" :aria-label="t('app.loading')">
      <a-spin size="large" />
    </div>

    <LoginView
      v-else-if="!authenticated"
      :is-dark="isDark"
      @toggle-theme="toggleTheme"
      @logged-in="onLoggedIn"
    />

    <div v-else class="panel-shell" :class="{ 'panel-shell--compact': collapsed }">
      <aside v-if="!mobile" class="panel-sidebar">
        <div class="panel-sidebar__inner">
          <div class="panel-brand" :title="t('app.title')">
            <span class="panel-brand__mark" aria-hidden="true"><ThunderboltFilled /></span>
            <span v-if="!collapsed" class="panel-brand__name">{{ t('app.title') }}</span>
          </div>
          <nav id="panel-navigation" :aria-label="t('app.navigation')">
            <a-menu
              v-model:selectedKeys="selectedKeys"
              class="panel-menu"
              mode="inline"
              :inline-collapsed="collapsed"
              :items="menuItems"
            />
          </nav>
          <a-button
            type="text"
            class="panel-sidebar__toggle"
            :aria-label="t('app.navigation')"
            :aria-expanded="!collapsed"
            aria-controls="panel-navigation"
            @click="collapsed = !collapsed"
          >
            <template #icon><MenuUnfoldOutlined v-if="collapsed" /><MenuFoldOutlined v-else /></template>
            {{ collapsed ? '' : t('app.navigation') }}
          </a-button>
        </div>
      </aside>

      <div class="panel-workspace">
        <header class="panel-toolbar">
          <div class="panel-toolbar__inner">
            <div class="panel-toolbar__context">
              <a-button
                v-if="mobile"
                class="panel-toolbar__icon"
                :aria-label="t('app.navigation')"
                :aria-expanded="navigationOpen"
                aria-haspopup="dialog"
                @click="navigationOpen = true"
              >
                <template #icon><MenuOutlined /></template>
              </a-button>
              <h1 id="panel-title">{{ currentTitle }}</h1>
            </div>

            <div class="panel-toolbar__actions">
              <span v-if="statusData?.shoes" class="panel-status" :class="{ 'panel-status--running': statusData.shoes.running }">
                Shoes · {{ t(statusData.shoes.running ? 'dashboard.running' : 'dashboard.stopped') }}
              </span>
              <a-radio-group
                :value="locale"
                class="panel-language"
                name="panel-language"
                aria-label="Language / 语言"
                @change="(e) => setLocale(e.target.value)"
              >
                <a-radio-button value="zh">中文</a-radio-button>
                <a-radio-button value="en">EN</a-radio-button>
              </a-radio-group>
              <a-button
                class="panel-toolbar__icon"
                :aria-label="t(isDark ? 'app.themeLight' : 'app.themeDark')"
                :title="t(isDark ? 'app.themeLight' : 'app.themeDark')"
                @click="toggleTheme"
              >
                <template #icon><BulbFilled v-if="isDark" /><BulbOutlined v-else /></template>
              </a-button>
              <a-dropdown :trigger="['click']">
                <a-button class="panel-toolbar__account" :aria-label="username" :title="username" aria-haspopup="menu">
                  <template #icon><UserOutlined /></template>
                  <span class="panel-toolbar__username">{{ username }}</span>
                </a-button>
                <template #overlay>
                  <a-menu>
                    <a-menu-item @click="doLogout">{{ t('app.logout') }}</a-menu-item>
                  </a-menu>
                </template>
              </a-dropdown>
            </div>
          </div>
        </header>

        <main class="panel-content" aria-labelledby="panel-title">
          <a-alert
            v-if="defaultCredentials && currentKey !== 'settings'"
            type="warning"
            show-icon
            closable
            :message="t('settings.defaultCredWarn')"
            style="margin-bottom: 14px"
          >
            <template #action>
              <a-button size="small" type="primary" danger @click="selectedKeys = ['settings']">
                {{ t('settings.changeNow') }}
              </a-button>
            </template>
          </a-alert>
          <div :key="currentKey" class="panel-view">
            <template v-if="currentKey === 'dashboard'">
              <DashboardView v-if="statusData" :status-data="statusData" @refresh="pollStatus" />
              <a-alert v-else-if="statusError" type="error" show-icon :message="statusError">
                <template #action><a-button @click="pollStatus">{{ t('app.refresh') }}</a-button></template>
              </a-alert>
              <div v-else class="panel-placeholder" role="status" :aria-label="t('app.loading')">
                <a-card v-for="index in 4" :key="index" aria-hidden="true">
                  <a-skeleton active :paragraph="{ rows: 1 }" />
                </a-card>
              </div>
            </template>
            <InboundsView v-else-if="currentKey === 'inbounds'" />
            <SubscriptionsView v-else-if="currentKey === 'subscriptions'" />
            <CertsView v-else-if="currentKey === 'certificates'" />
            <RoutingView v-else-if="currentKey === 'routing'" />
            <ConnectionsView v-else-if="currentKey === 'connections'" />
            <SettingsView
              v-else-if="currentKey === 'settings'"
              @logged-out="endSession"
              @navigate="(k) => (selectedKeys = [k])"
            />
          </div>
        </main>
      </div>

      <a-drawer
        v-if="mobile"
        v-model:open="navigationOpen"
        placement="left"
        width="min(19rem, calc(100vw - 2rem))"
        :title="t('app.title')"
        :body-style="{ padding: 'var(--panel-space-3)' }"
      >
        <nav :aria-label="t('app.navigation')">
          <a-menu
            v-model:selectedKeys="selectedKeys"
            class="panel-menu"
            mode="inline"
            :items="menuItems"
            @click="navigationOpen = false"
          />
        </nav>
      </a-drawer>
    </div>
  </a-config-provider>
</template>

<script setup>
import { computed, h, onMounted, onUnmounted, ref, watch } from 'vue';
import { theme } from 'ant-design-vue';
import zhCN from 'ant-design-vue/es/locale/zh_CN';
import enUS from 'ant-design-vue/es/locale/en_US';
import {
  DashboardOutlined,
  ClusterOutlined,
  ShareAltOutlined,
  SafetyCertificateOutlined,
  ApartmentOutlined,
  ApiOutlined,
  BulbFilled,
  BulbOutlined,
  MenuFoldOutlined,
  MenuOutlined,
  MenuUnfoldOutlined,
  SettingOutlined,
  ThunderboltFilled,
  UserOutlined,
} from '@ant-design/icons-vue';
import { useI18n } from 'vue-i18n';
import { api, onUnauthorized } from './api';
import { setLocale } from './i18n';

import LoginView from './views/LoginView.vue';
import DashboardView from './views/DashboardView.vue';
import InboundsView from './views/InboundsView.vue';
import SubscriptionsView from './views/SubscriptionsView.vue';
import CertsView from './views/CertsView.vue';
import RoutingView from './views/RoutingView.vue';
import ConnectionsView from './views/ConnectionsView.vue';
import SettingsView from './views/SettingsView.vue';

const { t, locale } = useI18n();

const ready = ref(false);
const authenticated = ref(false);
const username = ref('admin');
const defaultCredentials = ref(false);
const collapsed = ref(false);
const compactViewport = window.matchMedia('(max-width: 48rem)');
const mobile = ref(compactViewport.matches);
const navigationOpen = ref(false);
const selectedKeys = ref(['dashboard']);
const isDark = ref(localStorage.getItem('shoes_panel_theme') !== 'light');

const statusData = ref(null);
const statusError = ref('');
let session = 0;
let statusRequest = 0;
let appliedStatusRequest = 0;

const panelTheme = computed(() => ({
  algorithm: isDark.value ? theme.darkAlgorithm : theme.defaultAlgorithm,
  token: {
    fontFamily: 'var(--panel-font)',
    colorPrimary: isDark.value ? '#448df0' : '#0860cb',
    colorText: isDark.value ? '#edf2fa' : '#182336',
    colorTextSecondary: isDark.value ? '#a4b2c7' : '#4e5f76',
    colorBgContainer: isDark.value ? '#17202d' : '#ffffff',
    colorBgElevated: isDark.value ? '#1c2634' : '#ffffff',
    colorBgLayout: isDark.value ? '#101722' : '#eef2f7',
    colorBorderSecondary: isDark.value ? '#2a3748' : '#e4eaf2',
    borderRadius: 10,
    borderRadiusLG: 16,
    motionDurationFast: 'var(--panel-motion-fast)',
    motionDurationMid: 'var(--panel-motion-mid)',
    motionDurationSlow: 'var(--panel-motion-view)',
  },
}));

const currentKey = computed(() => selectedKeys.value[0] || 'dashboard');
const currentTitle = computed(() => t(`menu.${currentKey.value}`));

const menuItems = computed(() => [
  { key: 'dashboard', icon: () => h(DashboardOutlined), label: t('menu.dashboard') },
  { key: 'inbounds', icon: () => h(ClusterOutlined), label: t('menu.inbounds') },
  { key: 'subscriptions', icon: () => h(ShareAltOutlined), label: t('menu.subscriptions') },
  { key: 'certificates', icon: () => h(SafetyCertificateOutlined), label: t('menu.certificates') },
  { key: 'routing', icon: () => h(ApartmentOutlined), label: t('menu.routing') },
  { key: 'connections', icon: () => h(ApiOutlined), label: t('menu.connections') },
  { key: 'settings', icon: () => h(SettingOutlined), label: t('menu.settings') },
]);

watch(isDark, (dark) => {
  document.documentElement.dataset.panelTheme = dark ? 'dark' : 'light';
}, { immediate: true });

watch(locale, (language) => {
  document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
}, { immediate: true });

function toggleTheme() {
  isDark.value = !isDark.value;
  localStorage.setItem('shoes_panel_theme', isDark.value ? 'dark' : 'light');
}

async function pollStatus() {
  if (!authenticated.value) return;
  const request = ++statusRequest;
  const currentSession = session;
  try {
    const data = await api.status();
    if (currentSession === session && request > appliedStatusRequest) {
      appliedStatusRequest = request;
      statusData.value = data;
      statusError.value = '';
    }
  } catch (error) {
    if (currentSession === session && request === statusRequest) statusError.value = error.message;
  }
}

function onLoggedIn(payload) {
  if (typeof payload === 'string') {
    username.value = payload || 'admin';
  } else {
    username.value = payload?.username || 'admin';
    defaultCredentials.value = !!payload?.default_credentials;
  }
  authenticated.value = true;
  pollStatus();
}

async function doLogout() {
  await api.logout().catch(() => {});
  localStorage.removeItem('shoes_panel_token');
  endSession();
}

function endSession() {
  session += 1;
  authenticated.value = false;
  statusData.value = null;
  statusError.value = '';
  navigationOpen.value = false;
}

function updateViewport(event) {
  mobile.value = event.matches;
  if (!event.matches) navigationOpen.value = false;
}

let timer = null;
onMounted(async () => {
  compactViewport.addEventListener('change', updateViewport);
  onUnauthorized(endSession);
  try {
    const me = await api.me();
    if (me?.authenticated) {
      authenticated.value = true;
      username.value = me.username || 'admin';
      defaultCredentials.value = !!me.default_credentials;
      pollStatus();
    }
  } catch {}
  ready.value = true;
  timer = setInterval(pollStatus, 2000);
});

onUnmounted(() => {
  if (timer) clearInterval(timer);
  compactViewport.removeEventListener('change', updateViewport);
});
</script>
