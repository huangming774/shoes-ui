<template>
  <a-modal
    :open="open"
    :title="form.id ? t('app.edit') : t('inbounds.addClient')"
    width="520px"
    :confirm-loading="saving"
    @ok="handleSave"
    @cancel="emit('update:open', false)"
  >
    <a-form layout="vertical">
      <a-row :gutter="12">
        <a-col :span="14">
          <a-form-item :label="t('inbounds.clientName')" required>
            <a-input v-model:value="form.name" placeholder="alice" />
          </a-form-item>
        </a-col>
        <a-col :span="10">
          <a-form-item :label="t('app.enable')">
            <a-switch v-model:checked="form.enable" />
          </a-form-item>
        </a-col>
      </a-row>

      <template v-if="protocol === 'wireguard'">
        <a-form-item :label="t('inbounds.wgPeerAllowedIps')">
          <a-input v-model:value="form.wg_allowed_ips" placeholder="10.77.0.2/32, fd77::2/128 (留空自动分配)" />
        </a-form-item>
        <a-form-item :label="t('inbounds.wgPeerPrivKey')">
          <a-input-group compact>
            <a-input v-model:value="form.wg_private_key" style="width: calc(100% - 108px)" />
            <a-button style="width: 108px" @click="genWgPeerKeys">🔑 {{ t('inbounds.genRandom') }}</a-button>
          </a-input-group>
        </a-form-item>
        <a-form-item :label="t('inbounds.wgPeerPubKey')">
          <a-input v-model:value="form.wg_public_key" placeholder="Auto-derived if private key is set" />
        </a-form-item>
        <a-row :gutter="12">
          <a-col :span="16">
            <a-form-item :label="t('routing.wgPsk')">
              <a-input v-model:value="form.wg_preshared_key" placeholder="Optional Base64 PSK" />
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item :label="t('inbounds.wgPeerKeepalive')">
              <a-input-number v-model:value="form.wg_keepalive" :min="0" :max="65535" style="width: 100%" />
            </a-form-item>
          </a-col>
        </a-row>
      </template>

      <template v-else>
        <a-form-item v-if="['vless', 'vmess', 'tuic'].includes(protocol)" :label="t('inbounds.uuid')" required>
          <a-input-group compact>
            <a-input v-model:value="form.uuid" style="width: calc(100% - 92px)" />
            <a-button style="width: 92px" @click="genUuid">{{ t('inbounds.genRandom') }}</a-button>
          </a-input-group>
        </a-form-item>

        <a-form-item v-if="['naiveproxy', 'socks', 'http', 'mixed'].includes(protocol)" :label="t('inbounds.username')">
          <a-input v-model:value="form.username" placeholder="alice" />
        </a-form-item>

        <a-form-item
          v-if="!['vless', 'vmess'].includes(protocol)"
          :label="t('inbounds.password')"
        >
          <a-input-group compact>
            <a-input v-model:value="form.password" style="width: calc(100% - 92px)" />
            <a-button style="width: 92px" @click="genPwd">{{ t('inbounds.genRandom') }}</a-button>
          </a-input-group>
        </a-form-item>
      </template>

      <a-row :gutter="12">
        <a-col :span="12">
          <a-form-item :label="t('inbounds.subGroup')">
            <a-input v-model:value="form.sub_id" placeholder="default" />
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item :label="t('app.remark')">
            <a-input v-model:value="form.comment" />
          </a-form-item>
        </a-col>
      </a-row>
    </a-form>
  </a-modal>
</template>

<script setup>
import { reactive, ref, watch } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';

const props = defineProps({
  open: Boolean,
  inboundId: Number,
  protocol: { type: String, default: 'anytls' },
  cipher: { type: String, default: '' },
  record: { type: Object, default: null },
});
const emit = defineEmits(['update:open', 'saved']);
const { t } = useI18n();

const saving = ref(false);
const form = reactive({
  id: 0,
  name: '',
  enable: true,
  uuid: '',
  username: '',
  password: '',
  flow: '',
  sub_id: 'default',
  comment: '',
  wg_private_key: '',
  wg_public_key: '',
  wg_preshared_key: '',
  wg_allowed_ips: '',
  wg_keepalive: 25,
});

watch(
  () => props.open,
  async (v) => {
    if (!v) return;
    if (props.record && props.record.id) {
      Object.assign(
        form,
        {
          wg_private_key: '',
          wg_public_key: '',
          wg_preshared_key: '',
          wg_allowed_ips: '',
          wg_keepalive: 25,
        },
        props.record
      );
    } else {
      Object.assign(form, {
        id: 0,
        name: props.protocol === 'wireguard'
          ? `peer-${Math.floor(Math.random() * 900 + 100)}`
          : `user-${Math.floor(Math.random() * 900 + 100)}`,
        enable: true,
        uuid: '',
        username: `user${Math.floor(Math.random() * 90 + 10)}`,
        password: '',
        flow: '',
        sub_id: 'default',
        comment: '',
        wg_private_key: '',
        wg_public_key: '',
        wg_preshared_key: '',
        wg_allowed_ips: '',
        wg_keepalive: 25,
      });
      if (props.protocol === 'wireguard') {
        await genWgPeerKeys();
      } else {
        await genPwd();
        if (['vless', 'vmess', 'tuic'].includes(props.protocol)) {
          await genUuid();
        }
      }
    }
  }
);

async function genWgPeerKeys() {
  const res = await api.genWireguard();
  form.wg_private_key = res.private_key;
  form.wg_public_key = res.public_key;
  form.wg_preshared_key = res.preshared_key || '';
}

async function genUuid() {
  const { uuid } = await api.genUuid();
  form.uuid = uuid;
}

async function genPwd() {
  if (props.protocol === 'shadowsocks' && (props.cipher || '').startsWith('2022-blake3-')) {
    const { password } = await api.genSs2022(props.cipher);
    form.password = password;
  } else {
    const { secret } = await api.genRandom(20);
    form.password = secret;
  }
}

async function handleSave() {
  saving.value = true;
  try {
    if (form.id > 0) {
      await api.updateClient(form.id, { ...form });
    } else {
      await api.addClient(props.inboundId, { ...form });
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
