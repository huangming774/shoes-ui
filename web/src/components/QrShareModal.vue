<template>
  <a-modal
    :open="open"
    :title="title || t('inbounds.qrShare')"
    width="680px"
    :footer="null"
    @cancel="emit('update:open', false)"
  >
    <div v-if="items.length === 0" style="padding: 24px; text-align: center; opacity: 0.7">
      No shareable credentials
    </div>

    <a-tabs v-else v-model:activeKey="activeIdx">
      <a-tab-pane v-for="(item, idx) in items" :key="idx" :tab="item.name || `#${idx + 1}`">
        <div style="display: flex; flex-direction: column; align-items: center; gap: 16px">
          <div
            v-if="qrDataUrls[idx]"
            style="background: #fff; padding: 14px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.12)"
          >
            <img :src="qrDataUrls[idx]" alt="QR Code" style="width: 220px; height: 220px; display: block" />
          </div>

          <div v-if="item.uri" style="width: 100%">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-weight: 600">
              <span>{{ item.protocol === 'wireguard' ? t('inbounds.wgQrTitle') : 'URI / Share Link' }}</span>
              <a-space size="small">
                <a-button v-if="item.protocol === 'wireguard'" size="small" @click="downloadWgConf(item)">
                  ⬇ {{ t('inbounds.wgDownloadConf') }}
                </a-button>
                <a-button size="small" type="primary" @click="doCopy(item.uri)">
                  {{ item.protocol === 'wireguard' ? 'Copy .conf' : 'Copy URI' }}
                </a-button>
              </a-space>
            </div>
            <a-textarea
              :value="item.uri"
              :rows="item.protocol === 'wireguard' ? 11 : 3"
              readonly
              style="font-family: monospace; font-size: 12px"
            />
          </div>

          <a-collapse v-if="item.shoes_client_yaml" style="width: 100%" ghost>
            <a-collapse-panel key="shoes" header="Shoes Client Config Snippet (YAML)">
              <div style="display: flex; justify-content: flex-end; margin-bottom: 6px">
                <a-button size="small" @click="doCopy(item.shoes_client_yaml)">Copy YAML</a-button>
              </div>
              <pre
                style="max-height: 220px; overflow: auto; padding: 10px; border-radius: 8px; background: rgba(127,127,127,0.12); font-size: 12px; margin: 0"
              >{{ item.shoes_client_yaml }}</pre>
            </a-collapse-panel>
          </a-collapse>
        </div>
      </a-tab-pane>
    </a-tabs>
  </a-modal>
</template>

<script setup>
import { ref, watch } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import QRCode from 'qrcode';
import { copyText } from '../utils';

const props = defineProps({
  open: Boolean,
  title: String,
  items: { type: Array, default: () => [] },
});
const emit = defineEmits(['update:open']);
const { t } = useI18n();

const activeIdx = ref(0);
const qrDataUrls = ref({});

watch(
  () => [props.open, props.items],
  async ([isOpen, list]) => {
    if (!isOpen || !list?.length) return;
    activeIdx.value = 0;
    const map = {};
    for (let i = 0; i < list.length; i++) {
      const uri = list[i].uri || '';
      if (uri && !uri.includes(' = snell,')) {
        try {
          map[i] = await QRCode.toDataURL(uri, { width: 240, margin: 1 });
        } catch {
          map[i] = '';
        }
      }
    }
    qrDataUrls.value = map;
  },
  { immediate: true, deep: true }
);

async function doCopy(txt) {
  await copyText(txt);
  message.success(t('app.copied'));
}

function downloadWgConf(item) {
  const safeName = (item.name || 'wireguard-peer').replace(/[^a-zA-Z0-9._-]+/g, '_');
  const blob = new Blob([item.uri || ''], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${safeName}.conf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
</script>
