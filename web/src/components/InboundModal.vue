<template>
  <a-modal
    :open="open"
    :title="isEdit ? t('inbounds.modalEditTitle') : t('inbounds.modalAddTitle')"
    width="820px"
    :confirm-loading="saving"
    :ok-text="t('app.save')"
    :cancel-text="t('app.cancel')"
    @ok="handleSave"
    @cancel="emit('update:open', false)"
  >
    <a-form layout="vertical" style="max-height: 72vh; overflow-y: auto; padding-right: 8px">
      <!-- Basic Row -->
      <a-row :gutter="12">
        <a-col :span="10">
          <a-form-item :label="t('app.remark')" required>
            <a-input v-model:value="form.remark" placeholder="e.g. HK-VLESS-Reality" />
          </a-form-item>
        </a-col>
        <a-col :span="6">
          <a-form-item :label="t('inbounds.protocol')" required>
            <a-select v-model:value="form.protocol" @change="onProtocolChange">
              <a-select-option value="vless">VLESS</a-select-option>
              <a-select-option value="vmess">VMess</a-select-option>
              <a-select-option value="trojan">Trojan</a-select-option>
              <a-select-option value="shadowsocks">Shadowsocks (SS / 2022)</a-select-option>
              <a-select-option value="hysteria2">Hysteria2 (QUIC)</a-select-option>
              <a-select-option value="tuic">TUIC v5 (QUIC)</a-select-option>
              <a-select-option value="anytls">AnyTLS (Multi-User)</a-select-option>
              <a-select-option value="naiveproxy">NaiveProxy (Multi-User)</a-select-option>
              <a-select-option value="snell">Snell</a-select-option>
              <a-select-option value="socks">SOCKS5</a-select-option>
              <a-select-option value="http">HTTP / HTTPS</a-select-option>
              <a-select-option value="mixed">Mixed (HTTP+SOCKS5)</a-select-option>
            </a-select>
          </a-form-item>
        </a-col>
        <a-col :span="4">
          <a-form-item :label="t('inbounds.port')" required>
            <a-input-number v-model:value="form.port" :min="1" :max="65535" style="width: 100%" />
          </a-form-item>
        </a-col>
        <a-col :span="4">
          <a-form-item :label="t('app.enable')">
            <a-switch v-model:checked="form.enable" />
          </a-form-item>
        </a-col>
      </a-row>

      <!-- Quota, Expiry & Listen -->
      <a-row :gutter="12">
        <a-col :span="6">
          <a-form-item :label="t('inbounds.listenIp')">
            <a-input v-model:value="form.listen" placeholder="0.0.0.0" />
          </a-form-item>
        </a-col>
        <a-col :span="6">
          <a-form-item :label="t('inbounds.totalQuotaGb')">
            <a-input-number v-model:value="quotaGb" :min="0" :step="10" style="width: 100%" />
          </a-form-item>
        </a-col>
        <a-col :span="7">
          <a-form-item :label="t('inbounds.expiryDate')">
            <a-date-picker
              v-model:value="expiryDayjs"
              show-time
              style="width: 100%"
              format="YYYY-MM-DD HH:mm"
            />
          </a-form-item>
        </a-col>
        <a-col :span="5">
          <a-form-item :label="t('inbounds.autoResetDay')">
            <a-input-number v-model:value="form.auto_reset_day" :min="0" :max="31" style="width: 100%" />
          </a-form-item>
        </a-col>
      </a-row>

      <!-- Primary Client Credentials -->
      <a-divider orientation="left" style="margin: 8px 0 12px">{{ t('inbounds.primaryClient') }}</a-divider>
      <a-row :gutter="12">
        <a-col :span="8">
          <a-form-item :label="t('inbounds.clientName')">
            <a-input v-model:value="primaryClient.name" placeholder="client-1" />
          </a-form-item>
        </a-col>
        <a-col :span="8">
          <a-form-item :label="t('inbounds.subGroup')">
            <a-input v-model:value="primaryClient.sub_id" placeholder="default" />
          </a-form-item>
        </a-col>
        <a-col v-if="needsCipher" :span="8">
          <a-form-item :label="t('inbounds.cipher')">
            <a-select v-model:value="form.protocol_settings.cipher" @change="onCipherChange">
              <template v-if="form.protocol === 'shadowsocks'">
                <a-select-option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</a-select-option>
                <a-select-option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</a-select-option>
                <a-select-option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</a-select-option>
                <a-select-option value="aes-256-gcm">aes-256-gcm</a-select-option>
                <a-select-option value="aes-128-gcm">aes-128-gcm</a-select-option>
                <a-select-option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</a-select-option>
              </template>
              <template v-else-if="form.protocol === 'vmess'">
                <a-select-option value="any">auto / any</a-select-option>
                <a-select-option value="aes-128-gcm">aes-128-gcm</a-select-option>
                <a-select-option value="chacha20-poly1305">chacha20-poly1305</a-select-option>
                <a-select-option value="none">none</a-select-option>
              </template>
              <template v-else-if="form.protocol === 'snell'">
                <a-select-option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</a-select-option>
                <a-select-option value="aes-256-gcm">aes-256-gcm</a-select-option>
                <a-select-option value="aes-128-gcm">aes-128-gcm</a-select-option>
              </template>
            </a-select>
          </a-form-item>
        </a-col>
      </a-row>

      <a-row :gutter="12">
        <a-col v-if="needsUuid" :span="12">
          <a-form-item :label="t('inbounds.uuid')" required>
            <a-input-group compact>
              <a-input v-model:value="primaryClient.uuid" style="width: calc(100% - 92px)" />
              <a-button style="width: 92px" @click="refreshUuid">{{ t('inbounds.genRandom') }}</a-button>
            </a-input-group>
          </a-form-item>
        </a-col>

        <a-col v-if="needsUsername" :span="8">
          <a-form-item :label="t('inbounds.username')">
            <a-input v-model:value="primaryClient.username" placeholder="user1" />
          </a-form-item>
        </a-col>

        <a-col v-if="needsPassword" :span="needsUuid ? 12 : needsUsername ? 16 : 24">
          <a-form-item :label="t('inbounds.password')">
            <a-input-group compact>
              <a-input v-model:value="primaryClient.password" style="width: calc(100% - 92px)" />
              <a-button style="width: 92px" @click="refreshPassword">{{ t('inbounds.genRandom') }}</a-button>
            </a-input-group>
          </a-form-item>
        </a-col>
      </a-row>

      <!-- Transport & Security -->
      <a-divider orientation="left" style="margin: 8px 0 12px">{{ t('inbounds.transport') }}</a-divider>
      <a-row :gutter="12">
        <a-col :span="12">
          <a-form-item :label="t('inbounds.network')">
            <a-select
              v-model:value="form.stream_settings.network"
              :disabled="isQuicProtocol"
              @change="onNetworkChange"
            >
              <a-select-option v-if="!isQuicProtocol" value="tcp">TCP</a-select-option>
              <a-select-option v-if="supportsWs" value="ws">WebSocket (WS)</a-select-option>
              <a-select-option v-if="supportsXhttp" value="xhttp">XHTTP / SplitHTTP</a-select-option>
              <a-select-option v-if="isQuicProtocol || form.protocol === 'vless'" value="quic">QUIC / H3</a-select-option>
            </a-select>
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item :label="t('inbounds.security')">
            <a-select v-model:value="form.stream_settings.security" :disabled="isQuicOuter">
              <a-select-option v-if="!requiresTlsOrReality && !isQuicOuter" value="none">None</a-select-option>
              <a-select-option value="tls">TLS</a-select-option>
              <a-select-option v-if="supportsReality && !isQuicOuter" value="reality">REALITY</a-select-option>
            </a-select>
          </a-form-item>
        </a-col>
      </a-row>

      <!-- WebSocket Settings -->
      <div v-if="form.stream_settings.network === 'ws'" class="sub-box">
        <div class="sub-box-title">{{ t('inbounds.wsSettings') }}</div>
        <a-row :gutter="12">
          <a-col :span="10">
            <a-form-item :label="t('inbounds.wsPath')">
              <a-input v-model:value="form.stream_settings.ws.path" placeholder="/ws" />
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item :label="t('inbounds.wsHost')">
              <a-input v-model:value="form.stream_settings.ws.host" placeholder="cdn.example.com" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('inbounds.wsEarlyData')">
              <a-input-number v-model:value="form.stream_settings.ws.max_early_data" :min="0" :max="2048" style="width: 100%" />
            </a-form-item>
          </a-col>
        </a-row>
      </div>

      <!-- XHTTP Settings -->
      <div v-if="form.stream_settings.network === 'xhttp'" class="sub-box">
        <div class="sub-box-title">{{ t('inbounds.xhttpSettings') }}</div>
        <a-row :gutter="12">
          <a-col :span="9">
            <a-form-item :label="t('inbounds.xhttpPath')">
              <a-input v-model:value="form.stream_settings.xhttp.path" placeholder="/xhttp" />
            </a-form-item>
          </a-col>
          <a-col :span="9">
            <a-form-item :label="t('inbounds.xhttpHost')">
              <a-input v-model:value="form.stream_settings.xhttp.host" placeholder="example.com" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('inbounds.xhttpMode')">
              <a-select v-model:value="form.stream_settings.xhttp.mode">
                <a-select-option value="auto">auto</a-select-option>
                <a-select-option value="packet-up">packet-up</a-select-option>
                <a-select-option value="stream-up">stream-up</a-select-option>
                <a-select-option value="stream-one">stream-one</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>
      </div>

      <!-- TLS / QUIC Settings -->
      <div v-if="isQuicOuter || form.stream_settings.security === 'tls'" class="sub-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px">
          <span class="sub-box-title" style="margin-bottom: 0">{{ t('inbounds.tlsSettings') }}</span>
          <a-button size="small" type="dashed" @click="quickGenSelfSigned">
            ⚡ {{ t('certs.genSelfSigned') }}
          </a-button>
        </div>

        <a-row :gutter="12">
          <a-col :span="8">
            <a-form-item label="Mode">
              <a-select v-model:value="form.stream_settings.tls.cert_mode">
                <a-select-option value="source">{{ t('inbounds.certModeSource') }}</a-select-option>
                <a-select-option value="files">{{ t('inbounds.certModeFiles') }}</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col v-if="form.stream_settings.tls.cert_mode === 'source'" :span="8">
            <a-form-item :label="t('inbounds.certSource')" required>
              <a-select v-model:value="form.stream_settings.tls.certificate_source" placeholder="Select certificate">
                <a-select-option v-for="c in certs" :key="c.name" :value="c.name">
                  {{ c.name }} ({{ c.cert_type }})
                </a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item :label="t('inbounds.sni')">
              <a-input v-model:value="form.stream_settings.tls.sni" placeholder="proxy.example.com" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row v-if="form.stream_settings.tls.cert_mode === 'files'" :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.certFile')" required>
              <a-input v-model:value="form.stream_settings.tls.cert_file" placeholder="/etc/shoes/certs/fullchain.pem" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('inbounds.keyFile')" required>
              <a-input v-model:value="form.stream_settings.tls.key_file" placeholder="/etc/shoes/certs/privkey.pem" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :span="10">
            <a-form-item :label="t('inbounds.alpn')">
              <a-input v-model:value="alpnStr" placeholder="h2,http/1.1" />
            </a-form-item>
          </a-col>
          <a-col :span="14" style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap; padding-top: 12px">
            <a-checkbox v-if="!isQuicOuter" v-model:checked="form.stream_settings.tls.allow_any_sni">
              {{ t('inbounds.allowAnySni') }}
            </a-checkbox>
            <a-checkbox v-model:checked="form.stream_settings.tls.allow_insecure">
              {{ t('inbounds.allowInsecure') }}
            </a-checkbox>
            <a-checkbox
              v-if="form.protocol === 'vless' && form.stream_settings.network === 'tcp' && !isQuicOuter"
              v-model:checked="form.stream_settings.tls.vision"
            >
              {{ t('inbounds.vision') }}
            </a-checkbox>
          </a-col>
        </a-row>
      </div>

      <!-- REALITY Settings -->
      <div v-if="!isQuicOuter && form.stream_settings.security === 'reality'" class="sub-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px">
          <span class="sub-box-title" style="margin-bottom: 0">{{ t('inbounds.realitySettings') }}</span>
          <a-button size="small" type="primary" ghost @click="refreshRealityKeys">
            🔑 {{ t('inbounds.genRealityKeys') }}
          </a-button>
        </div>

        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.sni')" required>
              <a-input v-model:value="form.stream_settings.reality.sni" placeholder="www.microsoft.com" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('inbounds.realityDest')" required>
              <a-input v-model:value="form.stream_settings.reality.dest" placeholder="www.microsoft.com:443" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.realityPrivKey')" required>
              <a-input v-model:value="form.stream_settings.reality.private_key" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('inbounds.realityPubKey')">
              <a-input v-model:value="form.stream_settings.reality.public_key" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :span="14">
            <a-form-item :label="t('inbounds.realityShortIds')">
              <a-input v-model:value="shortIdsStr" placeholder="0123456789abcdef" />
            </a-form-item>
          </a-col>
          <a-col :span="10" style="display: flex; align-items: center; padding-top: 12px">
            <a-checkbox
              v-if="form.protocol === 'vless' && form.stream_settings.network === 'tcp'"
              v-model:checked="form.stream_settings.reality.vision"
            >
              {{ t('inbounds.vision') }}
            </a-checkbox>
          </a-col>
        </a-row>
      </div>

      <!-- Advanced & Routing -->
      <a-collapse ghost style="margin-top: 8px">
        <a-collapse-panel key="adv" :header="t('inbounds.advSettings')">
          <a-row :gutter="12">
            <a-col :span="8">
              <a-checkbox v-model:checked="form.protocol_settings.udp_enabled">
                {{ t('inbounds.udpEnabled') }}
              </a-checkbox>
            </a-col>
            <a-col :span="8">
              <a-checkbox v-model:checked="form.protocol_settings.sniff">
                {{ t('inbounds.sniff') }}
              </a-checkbox>
            </a-col>
            <a-col v-if="form.protocol === 'tuic'" :span="8">
              <a-checkbox v-model:checked="form.protocol_settings.zero_rtt_handshake">
                {{ t('inbounds.zeroRtt') }}
              </a-checkbox>
            </a-col>
          </a-row>
          <a-row :gutter="12" style="margin-top: 12px">
            <a-col :span="12">
              <a-form-item :label="t('inbounds.rulesRef')">
                <a-select v-model:value="form.protocol_settings.rules_ref" allow-clear placeholder="Default (Global Routing)">
                  <a-select-option value="">Default (Follow Global Routing)</a-select-option>
                  <a-select-option value="direct">Direct</a-select-option>
                  <a-select-option value="block">Block All</a-select-option>
                  <a-select-option v-for="g in outboundGroups" :key="g.name" :value="g.name">
                    Group: {{ g.name }}
                  </a-select-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item :label="t('inbounds.fallback')">
                <a-input v-model:value="form.protocol_settings.fallback" placeholder="127.0.0.1:80 or /var/www/html" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-form-item :label="t('inbounds.rawYaml')">
            <a-textarea
              v-model:value="form.protocol_settings.raw_override_yaml"
              :rows="4"
              style="font-family: monospace; font-size: 12px"
              placeholder="# Optional raw shoes ServerConfig YAML override"
            />
          </a-form-item>
        </a-collapse-panel>
      </a-collapse>
    </a-form>
  </a-modal>
</template>

<script setup>
import { computed, reactive, ref, watch } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import dayjs from 'dayjs';
import { api } from '../api';

const props = defineProps({
  open: Boolean,
  record: { type: Object, default: null },
  certs: { type: Array, default: () => [] },
  outboundGroups: { type: Array, default: () => [] },
});
const emit = defineEmits(['update:open', 'saved', 'certsChanged']);
const { t } = useI18n();

const saving = ref(false);
const isEdit = computed(() => Boolean(props.record && props.record.id > 0));

function blankInbound() {
  return {
    id: 0,
    remark: 'VLESS-Reality',
    enable: true,
    listen: '0.0.0.0',
    port: 20443,
    protocol: 'vless',
    total_quota_bytes: 0,
    expiry_time: 0,
    auto_reset_day: 0,
    protocol_settings: {
      udp_enabled: true,
      cipher: '',
      fallback: '',
      zero_rtt_handshake: false,
      padding: true,
      padding_scheme: [],
      sniff: false,
      rules_ref: '',
      raw_override_yaml: '',
    },
    stream_settings: {
      network: 'tcp',
      security: 'reality',
      tls: {
        sni: '',
        allow_any_sni: true,
        cert_mode: 'source',
        certificate_source: '',
        cert_file: '',
        key_file: '',
        alpn: [],
        vision: false,
        fingerprint: 'chrome',
        allow_insecure: false,
      },
      reality: {
        sni: 'www.microsoft.com',
        dest: 'www.microsoft.com:443',
        private_key: '',
        public_key: '',
        short_ids: ['0123456789abcdef'],
        vision: true,
        fingerprint: 'chrome',
        mldsa65_seed: '',
        mldsa65_verify: '',
      },
      ws: { path: '/ws', host: '', headers: {}, max_early_data: 0, early_data_header_name: '' },
      xhttp: { path: '/xhttp', host: '', mode: 'auto', headers: {} },
    },
    clients: [
      {
        id: 0,
        name: 'user-1',
        enable: true,
        uuid: '',
        password: '',
        username: 'user1',
        flow: 'xtls-rprx-vision',
        sub_id: 'default',
        comment: '',
      },
    ],
  };
}

const form = reactive(blankInbound());
const quotaGb = ref(0);
const expiryDayjs = ref(null);
const alpnStr = ref('');
const shortIdsStr = ref('0123456789abcdef');

const primaryClient = computed(() => {
  if (!form.clients || form.clients.length === 0) {
    form.clients = [blankInbound().clients[0]];
  }
  return form.clients[0];
});

const isQuicProtocol = computed(() => ['hysteria2', 'tuic'].includes(form.protocol));
const isQuicOuter = computed(() => isQuicProtocol.value || form.stream_settings.network === 'quic');
const requiresTlsOrReality = computed(() => ['anytls', 'naiveproxy'].includes(form.protocol));
const supportsReality = computed(() =>
  ['vless', 'trojan', 'anytls', 'naiveproxy', 'vmess', 'shadowsocks'].includes(form.protocol)
);
const supportsWs = computed(() =>
  ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks'].includes(form.protocol)
);
const supportsXhttp = computed(() => ['vless', 'vmess', 'trojan', 'shadowsocks'].includes(form.protocol));

const needsUuid = computed(() => ['vless', 'vmess', 'tuic'].includes(form.protocol));
const needsPassword = computed(() =>
  ['trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'naiveproxy', 'snell', 'socks', 'http', 'mixed'].includes(
    form.protocol
  )
);
const needsUsername = computed(() => ['naiveproxy', 'socks', 'http', 'mixed'].includes(form.protocol));
const needsCipher = computed(() => ['shadowsocks', 'vmess', 'snell'].includes(form.protocol));

watch(
  () => props.open,
  async (val) => {
    if (!val) return;
    if (props.record && props.record.id > 0) {
      const cloned = JSON.parse(JSON.stringify(props.record));
      Object.assign(form, blankInbound(), cloned);
      quotaGb.value = form.total_quota_bytes > 0 ? +(form.total_quota_bytes / 1073741824).toFixed(2) : 0;
      expiryDayjs.value = form.expiry_time > 0 ? dayjs(form.expiry_time) : null;
      alpnStr.value = (form.stream_settings.tls.alpn || []).join(',');
      shortIdsStr.value = (form.stream_settings.reality.short_ids || []).join(',');
    } else {
      Object.assign(form, blankInbound());
      quotaGb.value = 0;
      expiryDayjs.value = null;
      alpnStr.value = '';
      shortIdsStr.value = '0123456789abcdef';
      if (props.certs?.length > 0) {
        form.stream_settings.tls.certificate_source = props.certs[0].name;
      }
      try {
        const [{ port }, { uuid }, rk, rnd] = await Promise.all([
          api.nextPort(20000),
          api.genUuid(),
          api.genReality(),
          api.genRandom(20),
        ]);
        form.port = port;
        primaryClient.value.uuid = uuid;
        primaryClient.value.password = rnd.secret;
        form.stream_settings.reality.private_key = rk.private_key;
        form.stream_settings.reality.public_key = rk.public_key;
        shortIdsStr.value = rk.short_id;
      } catch {}
    }
  }
);

async function onProtocolChange(proto) {
  form.remark = `${proto.toUpperCase()}-${form.port}`;
  if (['hysteria2', 'tuic'].includes(proto)) {
    form.stream_settings.network = 'quic';
    form.stream_settings.security = 'tls';
  } else {
    if (form.stream_settings.network === 'quic') form.stream_settings.network = 'tcp';
    if (proto === 'vless') {
      form.stream_settings.security = 'reality';
    } else if (['trojan', 'anytls', 'naiveproxy'].includes(proto)) {
      form.stream_settings.security = 'tls';
      if (proto === 'naiveproxy' && !alpnStr.value) alpnStr.value = 'h2';
    } else {
      form.stream_settings.security = 'none';
    }
  }
  if (proto === 'shadowsocks') {
    form.protocol_settings.cipher = '2022-blake3-aes-256-gcm';
    await refreshPassword();
  } else if (proto === 'vmess') {
    form.protocol_settings.cipher = 'any';
  } else if (proto === 'snell') {
    form.protocol_settings.cipher = 'chacha20-ietf-poly1305';
  } else if (['socks', 'http', 'mixed'].includes(proto) && !isEdit.value) {
    primaryClient.value.username = '';
    primaryClient.value.password = '';
  }
}

function onNetworkChange(net) {
  if (net === 'quic') {
    form.stream_settings.security = 'tls';
  }
}

async function onCipherChange(cipher) {
  if (form.protocol === 'shadowsocks' && cipher.startsWith('2022-blake3-')) {
    await refreshPassword();
  }
}

async function refreshUuid() {
  const { uuid } = await api.genUuid();
  primaryClient.value.uuid = uuid;
}

async function refreshPassword() {
  if (form.protocol === 'shadowsocks' && (form.protocol_settings.cipher || '').startsWith('2022-blake3-')) {
    const { password } = await api.genSs2022(form.protocol_settings.cipher);
    primaryClient.value.password = password;
  } else {
    const { secret } = await api.genRandom(20);
    primaryClient.value.password = secret;
  }
}

async function refreshRealityKeys() {
  const rk = await api.genReality();
  form.stream_settings.reality.private_key = rk.private_key;
  form.stream_settings.reality.public_key = rk.public_key;
  shortIdsStr.value = rk.short_id;
}

async function quickGenSelfSigned() {
  try {
    const sni = form.stream_settings.tls.sni?.trim() || 'localhost';
    const name = `selfsigned-${Date.now().toString().slice(-5)}`;
    const cert = await api.selfSignedCert({
      name,
      domains: [sni, '127.0.0.1'],
      remark: `Auto Self-Signed (${sni})`,
    });
    emit('certsChanged');
    form.stream_settings.tls.cert_mode = 'source';
    form.stream_settings.tls.certificate_source = cert.name;
    form.stream_settings.tls.allow_insecure = true;
    message.success(`Created certificate source "${cert.name}"`);
  } catch (e) {
    message.error(e.message);
  }
}

async function handleSave() {
  saving.value = true;
  try {
    const payload = JSON.parse(JSON.stringify(form));
    payload.total_quota_bytes = Math.round(Number(quotaGb.value || 0) * 1073741824);
    payload.expiry_time = expiryDayjs.value ? expiryDayjs.value.valueOf() : 0;
    payload.stream_settings.tls.alpn = alpnStr.value
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    payload.stream_settings.reality.short_ids = shortIdsStr.value
      .split(',')
      .map((s) => s.trim());

    if (isEdit.value) {
      await api.updateInbound(payload.id, payload);
    } else {
      await api.createInbound(payload);
    }
    message.success(t('app.saveSuccess'));
    emit('update:open', false);
    emit('saved');
  } catch (e) {
    message.error(e.message);
  } finally {
    saving.value = false;
  }
}
</script>

<style scoped>
.sub-box {
  padding: 12px 14px 2px;
  margin-bottom: 12px;
  border-radius: 8px;
  border: 1px solid rgba(127, 127, 127, 0.22);
  background: rgba(127, 127, 127, 0.05);
}
.sub-box-title {
  font-weight: 600;
  margin-bottom: 10px;
  font-size: 13px;
}
</style>
