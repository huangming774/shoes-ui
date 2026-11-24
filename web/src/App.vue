<template>
  <a-config-provider
    :locale="locale === 'zh' ? zhCN : enUS"
    :theme="{
      algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
      token: { borderRadius: 8, colorPrimary: '#1677ff' },
    }"
  >
    <div v-if="!ready" style="min-height: 100vh; display: flex; align-items: center; justify-content: center">
      <a-spin size="large" />
    </div>

    <LoginView
      v-else-if="!authenticated"
      :is-dark="isDark"
      @toggle-theme="toggleTheme"
      @logged-in="onLoggedIn"
    />

    <a-layout v-else style="min-height: 100vh">
      <a-layout-sider
        v-model:collapsed="collapsed"
        collapsible
        breakpoint="lg"
        :theme="isDark ? 'dark' : 'light'"
        width="220"
      >
        <div class="logo-box">
          <span style="font-size: 18px">⚡</span>
          <span v-if="!collapsed" class="logo-title">Shoes Panel</span>
        </div>

        <a-menu
          v-model:selectedKeys="selectedKeys"
          mode="inline"
          :theme="isDark ? 'dark' : 'light'"
          :items="menuItems"
        />
      </a-layout-sider>

      <a-layout>
        <a-layout-header
          :style="{
            padding: '0 20px',
            height: '56px',
            lineHeight: '56px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: isDark ? '#141414' : '#ffffff',
            borderBottom: isDark ? '1px solid #262626' : '1px solid #f0f0f0',
          }"
        >
          <div style="display: flex; align-items: center; gap: 12px">
            <span style="font-weight: 700; font-size: 16px">{{ currentTitle }}</span>
            <a-tag :color="statusData?.shoes?.running ? 'success' : 'default'">
              shoes: {{ statusData?.shoes?.running ? t('dashboard.running') : t('dashboard.stopped') }}
            </a-tag>
          </div>

          <a-space :size="10">
            <a-radio-group
              :value="locale"
              size="small"
              button-style="solid"
              @change="(e) => setLocale(e.target.value)"
            >
              <a-radio-button value="zh">中文</a-radio-button>
              <a-radio-button value="en">EN</a-radio-button>
            </a-radio-group>

            <a-button size="small" @click="toggleTheme">
              {{ isDark ? '☀️' : '🌙' }}
            </a-button>

            <a-dropdown>
              <a-button size="small">👤 {{ username }}</a-button>
              <template #overlay>
                <a-menu>
                  <a-menu-item @click="doLogout">{{ t('app.logout') }}</a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
          </a-space>
        </a-layout-header>

        <a-layout-content style="padding: 18px; overflow-x: hidden">
          <DashboardView
            v-if="currentKey === 'dashboard'"
            :status-data="statusData"
            @refresh="pollStatus"
          />
          <InboundsView v-else-if="currentKey === 'inbounds'" />
          <SubscriptionsView v-else-if="currentKey === 'subscriptions'" />
          <CertsView v-else-if="currentKey === 'certificates'" />
          <RoutingView v-else-if="currentKey === 'routing'" />
          <ConnectionsView v-else-if="currentKey === 'connections'" />
          <SettingsView v-else-if="currentKey === 'settings'" @logged-out="authenticated = false" />
        </a-layout-content>
      </a-layout>
    </a-layout>
  </a-config-provider>
</template>

<script setup>
import { computed, h, onMounted, onUnmounted, ref } from 'vue';
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
  SettingOutlined,
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
const collapsed = ref(false);
const selectedKeys = ref(['dashboard']);
const isDark = ref(localStorage.getItem('shoes_panel_theme') !== 'light');

const statusData = ref({});

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

function applyBodyBg() {
  document.body.style.margin = '0';
  document.body.style.background = isDark.value ? '#0a0a0a' : '#f5f7fa';
  document.body.style.color = isDark.value ? '#e6e6e6' : '#1f1f1f';
}

function toggleTheme() {
  isDark.value = !isDark.value;
  localStorage.setItem('shoes_panel_theme', isDark.value ? 'dark' : 'light');
  applyBodyBg();
}

async function pollStatus() {
  if (!authenticated.value) return;
  try {
    statusData.value = await api.status();
  } catch {}
}

function onLoggedIn(u) {
  username.value = u || 'admin';
  authenticated.value = true;
  pollStatus();
}

async function doLogout() {
  await api.logout().catch(() => {});
  localStorage.removeItem('shoes_panel_token');
  authenticated.value = false;
}

let timer = null;
onMounted(async () => {
  applyBodyBg();
  onUnauthorized(() => {
    authenticated.value = false;
  });
  try {
    const me = await api.me();
    if (me?.authenticated) {
      authenticated.value = true;
      username.value = me.username || 'admin';
      await pollStatus();
    }
  } catch {}
  ready.value = true;
  timer = setInterval(pollStatus, 2000);
});

onUnmounted(() => {
  if (timer) clearInterval(timer);
});
</script>

<style>
* {
  box-sizing: border-box;
}
.logo-box {
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  font-weight: 800;
  font-size: 16px;
  border-bottom: 1px solid rgba(127, 127, 127, 0.14);
}
.logo-title {
  background: linear-gradient(90deg, #1677ff, #722ed1);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
</style>
