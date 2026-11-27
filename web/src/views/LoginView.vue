<template>
  <div class="login-bg">
    <div class="login-topbar">
      <a-space>
        <a-button @click="emit('toggleTheme')">
          <template #icon><BulbFilled v-if="isDark" /><BulbOutlined v-else /></template>
          {{ t(isDark ? 'app.themeLight' : 'app.themeDark') }}
        </a-button>
        <a-select
          :value="locale"
          class="panel-language"
          style="min-width: 126px"
          aria-label="Language"
          @change="(val) => setLocale(val)"
        >
          <a-select-option v-for="item in SUPPORTED_LOCALES" :key="item.code" :value="item.code">
            🌐 {{ item.label }}
          </a-select-option>
        </a-select>
      </a-space>
    </div>

    <main class="login-card">
      <section
        ref="brandArtRef"
        class="brand-art"
        :class="{ 'brand-art--active': formFocused, 'brand-art--busy': loading }"
        :style="parallaxStyle"
        aria-labelledby="login-brand"
        @pointermove="onArtPointerMove"
        @pointerleave="onArtPointerLeave"
      >
        <div class="art-aurora" aria-hidden="true"></div>
        <div class="art-spotlight" aria-hidden="true"></div>

        <div class="circuit" aria-hidden="true">
          <!-- Isometric circuit plane aligned with the core chip center -->
          <div class="iso-plane">
            <div class="iso-grid"></div>

            <!-- Concentric isometric signal ripples -->
            <div class="iso-ring iso-ring--1"></div>
            <div class="iso-ring iso-ring--2"></div>
            <div class="iso-ring iso-ring--3"></div>

            <!-- Animated fiber-optic traces & streaming packets -->
            <svg class="iso-traces" viewBox="0 0 420 420" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="trace-beam-h" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stop-color="#6ef7e4" stop-opacity="0" />
                  <stop offset="50%" stop-color="#a8fff3" stop-opacity="0.95" />
                  <stop offset="100%" stop-color="#6ef7e4" stop-opacity="0" />
                </linearGradient>
                <filter id="trace-glow" x="-30%" y="-30%" width="160%" height="160%">
                  <feGaussianBlur stdDeviation="2.4" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              <!-- Base static circuit bus tracks -->
              <g stroke="#7be7e1" stroke-opacity="0.22" stroke-width="1.2">
                <path d="M 10 210 H 410" />
                <path d="M 210 10 V 410" />
                <path d="M 30 166 H 158 L 178 186" />
                <path d="M 390 254 H 262 L 242 234" />
                <path d="M 166 30 V 158 L 186 178" />
                <path d="M 254 390 V 262 L 234 242" />
                <path d="M 55 254 H 150 L 170 234" />
                <path d="M 365 166 H 270 L 250 186" />
                <path d="M 166 365 V 270 L 186 250" />
                <path d="M 254 55 V 150 L 234 170" />
              </g>

              <!-- Animated data streams flowing through the core -->
              <g filter="url(#trace-glow)" stroke-linecap="round" stroke-width="2.1">
                <path class="trace-flow flow-a" d="M 10 210 H 410" stroke="#7ff9e8" />
                <path class="trace-flow flow-b" d="M 210 410 V 10" stroke="#5fe2f8" />
                <path class="trace-flow flow-c" d="M 30 166 H 158 L 178 186" stroke="#a6fff2" />
                <path class="trace-flow flow-d" d="M 390 254 H 262 L 242 234" stroke="#7ff9e8" />
                <path class="trace-flow flow-e" d="M 166 30 V 158 L 186 178" stroke="#64e6f5" />
                <path class="trace-flow flow-f" d="M 254 390 V 262 L 234 242" stroke="#a6fff2" />
                <path class="trace-flow flow-g" d="M 55 254 H 150 L 170 234" stroke="#5fe2f8" />
                <path class="trace-flow flow-h" d="M 365 166 H 270 L 250 186" stroke="#7ff9e8" />
              </g>

              <!-- Twinkling terminal beacons -->
              <g fill="#b5fff5" filter="url(#trace-glow)">
                <circle class="beacon beacon-1" cx="72" cy="210" r="2.6" />
                <circle class="beacon beacon-2" cx="348" cy="210" r="2.6" />
                <circle class="beacon beacon-3" cx="210" cy="72" r="2.6" />
                <circle class="beacon beacon-4" cx="210" cy="348" r="2.6" />
                <circle class="beacon beacon-2" cx="110" cy="166" r="2.2" />
                <circle class="beacon beacon-1" cx="310" cy="254" r="2.2" />
                <circle class="beacon beacon-4" cx="166" cy="110" r="2.2" />
                <circle class="beacon beacon-3" cx="254" cy="310" r="2.2" />
              </g>
            </svg>
          </div>

          <!-- Soft ambient floating particles -->
          <div class="ambient-sparks">
            <span class="spark spark-1"></span>
            <span class="spark spark-2"></span>
            <span class="spark spark-3"></span>
            <span class="spark spark-4"></span>
            <span class="spark spark-5"></span>
            <span class="spark spark-6"></span>
          </div>

          <!-- 3-Layer Floating Isometric Core Chip -->
          <div class="chip-stack">
            <div class="chip-shadow"></div>
            <div class="chip-layer chip-layer--base">
              <div class="chip chip-base"></div>
            </div>
            <div class="chip-layer chip-layer--middle">
              <div class="chip chip-middle"></div>
            </div>
            <div class="chip-layer chip-layer--top">
              <div class="chip chip-top">
                <span class="chip-sheen"></span>
                <ThunderboltFilled class="chip-bolt" />
              </div>
            </div>
          </div>
        </div>

        <div class="brand-caption">
          <p id="login-brand" class="wordmark">Shoes<span>Panel</span></p>
          <p class="brand-subtitle">{{ t('app.subtitle') }}</p>
          <div class="proto-marquee" aria-hidden="true">
            <div class="proto-track">
              <span v-for="(item, idx) in MARQUEE_PROTOCOLS" :key="`a-${idx}`" class="proto-pill">
                <i class="proto-dot"></i>{{ item }}
              </span>
              <span v-for="(item, idx) in MARQUEE_PROTOCOLS" :key="`b-${idx}`" class="proto-pill">
                <i class="proto-dot"></i>{{ item }}
              </span>
            </div>
          </div>
        </div>
      </section>

      <div class="login-form">
        <header class="login-heading">
          <h1>{{ t('app.loginTitle') }}</h1>
        </header>

        <a-form layout="vertical" @submit="onSubmit">
          <a-form-item :label="t('app.username')" html-for="panel-login-username">
            <a-input
              id="panel-login-username"
              v-model:value="username"
              size="large"
              autocomplete="username"
              @focus="formFocused = true"
              @blur="formFocused = false"
            >
              <template #prefix><UserOutlined aria-hidden="true" /></template>
            </a-input>
          </a-form-item>
          <a-form-item :label="t('app.password')" html-for="panel-login-password">
            <a-input-password
              id="panel-login-password"
              v-model:value="password"
              size="large"
              autocomplete="current-password"
              @focus="formFocused = true"
              @blur="formFocused = false"
            >
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
import { computed, ref } from 'vue';
import { message } from 'ant-design-vue';
import { BulbFilled, BulbOutlined, LockOutlined, ThunderboltFilled, UserOutlined } from '@ant-design/icons-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { setLocale, SUPPORTED_LOCALES } from '../i18n';

defineProps({ isDark: Boolean });
const emit = defineEmits(['loggedIn', 'toggleTheme']);
const { t, locale } = useI18n();

const MARQUEE_PROTOCOLS = [
  'VLESS · REALITY',
  'Hysteria2',
  'TUIC v5',
  'AnyTLS',
  'WireGuard',
  'VMess',
  'Trojan',
  'SS-2022',
  'NaiveProxy',
  'Snell',
  'Cluster',
];

const username = ref('');
const password = ref('');
const loading = ref(false);
const formFocused = ref(false);

const brandArtRef = ref(null);
const px = ref(0);
const py = ref(0);
const spotX = ref(56);
const spotY = ref(38);
const pointerInside = ref(false);

const parallaxStyle = computed(() => ({
  '--px': px.value.toFixed(3),
  '--py': py.value.toFixed(3),
  '--spot-x': `${spotX.value.toFixed(1)}%`,
  '--spot-y': `${spotY.value.toFixed(1)}%`,
  '--spot-opacity': pointerInside.value ? '1' : '0',
}));

function onArtPointerMove(event) {
  const el = brandArtRef.value;
  if (!el) return;
  const rect = el.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const nx = Math.max(-1, Math.min(1, ((event.clientX - rect.left) / rect.width) * 2 - 1));
  const ny = Math.max(-1, Math.min(1, ((event.clientY - rect.top) / rect.height) * 2 - 1));
  px.value = nx;
  py.value = ny;
  spotX.value = ((event.clientX - rect.left) / rect.width) * 100;
  spotY.value = ((event.clientY - rect.top) / rect.height) * 100;
  pointerInside.value = true;
}

function onArtPointerLeave() {
  px.value = 0;
  py.value = 0;
  pointerInside.value = false;
}

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
  min-height: 30rem;
  display: flex;
  align-items: flex-end;
  padding: clamp(1.5rem, 4vw, 2.75rem);
  color: #eaffff;
  background: radial-gradient(ellipse at 56% 35%, #145966 0%, #10333f 42%, #081a26 80%);
  --px: 0;
  --py: 0;
  --spot-x: 56%;
  --spot-y: 38%;
  --spot-opacity: 0;
  --flow-speed: 1;
}

.brand-art--busy {
  --flow-speed: 0.48;
}

/* Slowly drifting volumetric cyan/emerald aurora backdrop */
.art-aurora {
  position: absolute;
  inset: -35%;
  z-index: -3;
  opacity: 0.8;
  background:
    radial-gradient(circle at 38% 34%, rgba(74, 240, 224, 0.24), transparent 46%),
    radial-gradient(circle at 72% 62%, rgba(36, 178, 224, 0.2), transparent 50%),
    radial-gradient(circle at 52% 24%, rgba(132, 255, 232, 0.14), transparent 40%);
  filter: blur(22px);
  animation: aurora-drift 13s ease-in-out infinite alternate;
  transition: opacity 0.45s ease, filter 0.45s ease;
}

.brand-art--active .art-aurora {
  opacity: 1;
  filter: blur(18px) brightness(1.16);
}

/* Interactive soft pointer glow */
.art-spotlight {
  position: absolute;
  inset: 0;
  z-index: -2;
  pointer-events: none;
  opacity: var(--spot-opacity);
  background: radial-gradient(
    20rem circle at var(--spot-x) var(--spot-y),
    rgba(130, 255, 238, 0.16),
    rgba(42, 180, 200, 0.05) 45%,
    transparent 72%
  );
  transition: opacity 0.35s ease;
}

.circuit {
  position: absolute;
  inset: 0;
  z-index: -1;
  pointer-events: none;
}

/* Isometric circuit plane centered directly under the core chip */
.iso-plane {
  position: absolute;
  top: 39%;
  left: 50%;
  width: 31rem;
  height: 31rem;
  transform: translate(
      calc(-50% + var(--px) * -8px),
      calc(-50% + var(--py) * -6px)
    )
    rotateX(54deg)
    rotateZ(-38deg);
  transition: transform 0.35s cubic-bezier(0.22, 1, 0.36, 1);
  will-change: transform;
}

.iso-grid {
  position: absolute;
  inset: -15%;
  background-image: linear-gradient(#7cdddf26 1px, transparent 1px),
    linear-gradient(90deg, #7cdddf26 1px, transparent 1px),
    radial-gradient(circle at 1px 1px, #8acfcf99 1.4px, transparent 2px);
  background-size: 2.2rem 2.2rem;
  mask-image: radial-gradient(ellipse at center, black 18%, transparent 66%);
  animation: grid-drift 20s linear infinite;
}

.iso-traces {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  mask-image: radial-gradient(circle at center, black 34%, transparent 72%);
}

.trace-flow {
  stroke-dasharray: 28 240;
  stroke-dashoffset: 268;
  animation: trace-travel calc(4.2s * var(--flow-speed)) linear infinite;
}
.flow-b {
  stroke-dasharray: 34 260;
  animation-duration: calc(4.8s * var(--flow-speed));
  animation-delay: -1.6s;
}
.flow-c {
  stroke-dasharray: 22 180;
  animation-duration: calc(3.6s * var(--flow-speed));
  animation-delay: -0.7s;
}
.flow-d {
  stroke-dasharray: 22 180;
  animation-duration: calc(3.9s * var(--flow-speed));
  animation-delay: -2.2s;
}
.flow-e {
  stroke-dasharray: 20 180;
  animation-duration: calc(3.4s * var(--flow-speed));
  animation-delay: -1.1s;
}
.flow-f {
  stroke-dasharray: 24 185;
  animation-duration: calc(4.1s * var(--flow-speed));
  animation-delay: -2.8s;
}
.flow-g {
  stroke-dasharray: 18 170;
  animation-duration: calc(3.7s * var(--flow-speed));
  animation-delay: -0.3s;
}
.flow-h {
  stroke-dasharray: 18 170;
  animation-duration: calc(4.4s * var(--flow-speed));
  animation-delay: -1.9s;
}

.beacon {
  transform-box: fill-box;
  transform-origin: center;
  animation: beacon-pulse 3.2s ease-in-out infinite;
}
.beacon-2 { animation-delay: -0.8s; }
.beacon-3 { animation-delay: -1.6s; }
.beacon-4 { animation-delay: -2.4s; }

/* Concentric isometric diamond waves expanding from the chip */
.iso-ring {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 9.8rem;
  height: 9.8rem;
  border-radius: 18%;
  border: 1.5px solid rgba(124, 245, 232, 0.52);
  box-shadow: 0 0 18px rgba(102, 255, 230, 0.22);
  transform: translate(-50%, -50%) scale(0.92);
  opacity: 0;
  animation: iso-ripple calc(4.8s * var(--flow-speed)) cubic-bezier(0.18, 0.62, 0.26, 1) infinite;
}
.iso-ring--2 { animation-delay: calc(-1.6s * var(--flow-speed)); }
.iso-ring--3 { animation-delay: calc(-3.2s * var(--flow-speed)); }

/* Ambient rising micro-sparks */
.ambient-sparks {
  position: absolute;
  inset: 0;
}
.spark {
  position: absolute;
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: #a5fff2;
  box-shadow: 0 0 10px #72f6e5, 0 0 18px rgba(114, 246, 229, 0.5);
  opacity: 0;
  animation: spark-rise 7.5s ease-in-out infinite;
}
.spark-1 { left: 26%; top: 56%; animation-delay: 0s; animation-duration: 7.2s; }
.spark-2 { left: 72%; top: 50%; animation-delay: -2.1s; animation-duration: 8.4s; }
.spark-3 { left: 42%; top: 62%; width: 3px; height: 3px; animation-delay: -4.2s; animation-duration: 6.8s; }
.spark-4 { left: 61%; top: 44%; width: 3px; height: 3px; animation-delay: -1.4s; animation-duration: 7.8s; }
.spark-5 { left: 34%; top: 34%; width: 2.5px; height: 2.5px; animation-delay: -5.3s; animation-duration: 9s; }
.spark-6 { left: 78%; top: 36%; width: 2.5px; height: 2.5px; animation-delay: -3.2s; animation-duration: 8s; }

/* 3-Layer Floating Isometric Chip Stack */
.chip-stack {
  position: absolute;
  top: 39%;
  left: 50%;
  width: 10rem;
  aspect-ratio: 1;
  transform: translate(-50%, -50%);
}

.chip-shadow {
  position: absolute;
  inset: 8%;
  border-radius: 22%;
  background: radial-gradient(circle, rgba(2, 16, 24, 0.78) 0%, rgba(18, 92, 104, 0.35) 55%, transparent 78%);
  transform: translateY(3.3rem) rotateX(52deg) rotateZ(-38deg);
  filter: blur(10px);
  animation: shadow-breathe 5.2s ease-in-out infinite;
}

.chip-layer {
  position: absolute;
  inset: 0;
  transition: transform 0.35s cubic-bezier(0.22, 1, 0.36, 1);
  will-change: transform;
}

.chip-layer--base {
  transform: translate3d(calc(var(--px) * 4px), calc(var(--py) * 3px), 0);
}
.chip-layer--middle {
  transform: translate3d(calc(var(--px) * 9px), calc(var(--py) * 7px), 0);
}
.chip-layer--top {
  transform: translate3d(calc(var(--px) * 14px), calc(var(--py) * 11px), 0);
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
  animation: float-base 5.2s ease-in-out infinite;
}

.chip-middle {
  --lift: 0.9rem;
  background: linear-gradient(135deg, #8efae4b8, #207e8988 70%);
  box-shadow: 0 5px #215f68, 0 8px 24px rgba(102, 255, 230, 0.3);
  animation: float-middle 5.2s ease-in-out infinite;
}

.chip-top {
  --lift: -0.55rem;
  overflow: hidden;
  background: linear-gradient(140deg, #b8fff3, #62d8cd 26%, #398c96 65%, #244552);
  box-shadow:
    inset 0 0 0 6px #c6fff333,
    inset 0 0 0 7px #eaffff66,
    0 5px #326875,
    0 12px 28px rgba(88, 245, 224, 0.28);
  animation: float-top 5.2s ease-in-out infinite;
}

/* Periodic glass reflection sweeping across the top chip */
.chip-sheen {
  position: absolute;
  inset: -40%;
  background: linear-gradient(
    112deg,
    transparent 36%,
    rgba(255, 255, 255, 0.45) 48%,
    rgba(220, 255, 250, 0.14) 54%,
    transparent 64%
  );
  transform: translateX(-110%);
  animation: chip-sheen-sweep 5.8s ease-in-out infinite;
}

.chip-bolt {
  position: relative;
  z-index: 1;
  font-size: 4rem;
  color: #f0fffc;
  animation: bolt-glow calc(3.4s * var(--flow-speed)) ease-in-out infinite;
}

.brand-caption {
  position: relative;
  z-index: 1;
  width: 100%;
  min-width: 0;
}
.brand-caption p {
  margin: 0;
  color: #b6d8dd;
}
.brand-caption .wordmark {
  color: #f1fffd;
  font: 700 clamp(2.5rem, 4.8vw, 3.85rem)/1.1 var(--panel-font);
  letter-spacing: -0.065em;
  margin-bottom: 0.45rem;
}
.wordmark span {
  color: #86eee1;
  font-weight: 350;
}
.brand-subtitle {
  font-size: 0.92rem;
}

/* Sleek protocol marquee strip */
.proto-marquee {
  direction: ltr;
  margin-top: 0.95rem;
  overflow: hidden;
  mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent);
}
.proto-track {
  display: inline-flex;
  align-items: center;
  gap: 0.55rem;
  width: max-content;
  animation: proto-scroll 26s linear infinite;
}
.brand-art:hover .proto-track {
  animation-play-state: paused;
}
.proto-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.2rem 0.6rem;
  border-radius: 999px;
  border: 1px solid rgba(134, 238, 225, 0.22);
  background: rgba(12, 42, 54, 0.48);
  color: rgba(212, 245, 242, 0.88);
  font-size: 0.72rem;
  font-weight: 500;
  letter-spacing: 0.01em;
  white-space: nowrap;
}
.proto-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: #7cf7e4;
  box-shadow: 0 0 6px #7cf7e4;
}

/* Keyframes */
@keyframes aurora-drift {
  0% { transform: translate(-4%, -3%) scale(1); }
  50% { transform: translate(4%, 3%) scale(1.06); }
  100% { transform: translate(-2%, 5%) scale(1.02); }
}

@keyframes grid-drift {
  0% { background-position: 0 0, 0 0, 0 0; }
  100% { background-position: 2.2rem 2.2rem, 2.2rem 2.2rem, 2.2rem 2.2rem; }
}

@keyframes trace-travel {
  0% { stroke-dashoffset: 268; opacity: 0.15; }
  12% { opacity: 1; }
  85% { opacity: 0.95; }
  100% { stroke-dashoffset: -40; opacity: 0; }
}

@keyframes beacon-pulse {
  0%, 100% { opacity: 0.28; transform: scale(0.8); }
  50% { opacity: 1; transform: scale(1.35); }
}

@keyframes iso-ripple {
  0% { transform: translate(-50%, -50%) scale(0.9); opacity: 0; }
  16% { opacity: 0.62; }
  100% { transform: translate(-50%, -50%) scale(2.45); opacity: 0; }
}

@keyframes spark-rise {
  0% { transform: translateY(16px) scale(0.6); opacity: 0; }
  25% { opacity: 0.85; }
  75% { opacity: 0.6; }
  100% { transform: translateY(-48px) scale(0.35); opacity: 0; }
}

@keyframes shadow-breathe {
  0%, 100% { transform: translateY(3.3rem) rotateX(52deg) rotateZ(-38deg) scale(1); opacity: 0.72; }
  50% { transform: translateY(3.3rem) rotateX(52deg) rotateZ(-38deg) scale(0.88); opacity: 0.48; }
}

@keyframes float-base {
  0%, 100% { transform: translateY(var(--lift)) rotateX(52deg) rotateZ(-38deg); }
  50% { transform: translateY(calc(var(--lift) - 0.18rem)) rotateX(52deg) rotateZ(-38deg); }
}

@keyframes float-middle {
  0%, 100% {
    transform: translateY(var(--lift)) rotateX(52deg) rotateZ(-38deg);
    box-shadow: 0 5px #215f68, 0 8px 20px rgba(102, 255, 230, 0.24);
  }
  50% {
    transform: translateY(calc(var(--lift) - 0.42rem)) rotateX(52deg) rotateZ(-38deg);
    box-shadow: 0 6px #215f68, 0 12px 30px rgba(102, 255, 230, 0.46);
  }
}

@keyframes float-top {
  0%, 100% {
    transform: translateY(var(--lift)) rotateX(52deg) rotateZ(-38deg);
    box-shadow:
      inset 0 0 0 6px #c6fff330,
      inset 0 0 0 7px #eaffff5a,
      0 5px #326875,
      0 10px 24px rgba(88, 245, 224, 0.22);
  }
  50% {
    transform: translateY(calc(var(--lift) - 0.68rem)) rotateX(52deg) rotateZ(-38deg);
    box-shadow:
      inset 0 0 0 6px #c6fff344,
      inset 0 0 0 7px #eaffff88,
      0 6px #326875,
      0 18px 34px rgba(112, 255, 236, 0.42);
  }
}

@keyframes chip-sheen-sweep {
  0%, 62% { transform: translateX(-115%); }
  88%, 100% { transform: translateX(115%); }
}

@keyframes bolt-glow {
  0%, 100% {
    filter: drop-shadow(0 2px 4px #124c57) drop-shadow(0 0 6px rgba(176, 255, 244, 0.35));
    transform: scale(1);
  }
  50% {
    filter: drop-shadow(0 2px 5px #124c57) drop-shadow(0 0 16px rgba(176, 255, 244, 0.85));
    transform: scale(1.05);
  }
}

@keyframes proto-scroll {
  0% { transform: translateX(0); }
  100% { transform: translateX(-50%); }
}

.login-form {
  align-self: center;
  padding: clamp(1.5rem, 4vw, 3rem);
}
.login-form :deep(.ant-input-affix-wrapper) { min-height: 2.85rem; border-radius: .65rem; }
.login-form :deep(.ant-input-prefix) { color: var(--panel-muted); margin-inline-end: .7rem; }
.login-form :deep(.ant-form-item-label label) { font-weight: 550; }

@media (max-width: 44rem) {
  .login-card { grid-template-columns: minmax(0, 1fr); max-width: 28rem; }
  .brand-art { min-height: 10rem; padding: 1.35rem; }
  .brand-caption { max-width: 68%; }
  .brand-caption .wordmark { font-size: 2.2rem; }
  .brand-subtitle { font-size: .8rem; }
  .proto-marquee { display: none; }
  .iso-plane { top: 44%; left: 81%; width: 17rem; height: 17rem; }
  .iso-ring { width: 4.8rem; height: 4.8rem; }
  .chip-stack { top: 44%; left: 81%; width: 4.8rem; }
  :dir(rtl) .iso-plane,
  :dir(rtl) .chip-stack { left: 19%; }
  .chip-bolt { font-size: 2.3rem; }
  .chip-base { --lift: 1.1rem; }
  .chip-middle { --lift: 0.4rem; }
  .chip-top { --lift: -0.25rem; }
  .chip-shadow { transform: translateY(1.6rem) rotateX(52deg) rotateZ(-38deg); }
}

@media (prefers-reduced-motion: reduce) {
  .art-aurora,
  .iso-grid,
  .trace-flow,
  .beacon,
  .iso-ring,
  .spark,
  .chip-shadow,
  .chip-base,
  .chip-middle,
  .chip-top,
  .chip-sheen,
  .chip-bolt,
  .proto-track {
    animation: none !important;
  }
  .trace-flow,
  .iso-ring,
  .spark,
  .chip-sheen {
    opacity: 0 !important;
  }
  .chip-layer {
    transform: none;
  }
  .iso-plane {
    transform: translate(-50%, -50%) rotateX(54deg) rotateZ(-38deg);
  }
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
