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
              <a-select-option value="portforward">PortForward (TCP 转发)</a-select-option>
              <a-select-option value="wireguard">WireGuard (VPN 服务端 · Multi-Peer)</a-select-option>
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

      <!-- Optional Port Range / Hysteria2 Port Hopping -->
      <a-row v-if="form.protocol === 'hysteria2' || form.protocol === 'portforward' || form.protocol_settings.port_range" :gutter="12">
        <a-col :span="24">
          <a-form-item :label="t('inbounds.portRange')">
            <a-input
              v-model:value="form.protocol_settings.port_range"
              placeholder="e.g. 20000-20100 or 20000,20010-20020 (Hysteria2 hopping auto-synced to subscriptions)"
            />
          </a-form-item>
        </a-col>
      </a-row>

      <!-- PortForward Target Addresses -->
      <div v-if="isPortForward" class="sub-box">
        <div class="sub-box-title">PortForward</div>
        <a-alert type="info" show-icon :message="t('inbounds.forwardTip')" style="margin-bottom: 10px; font-size: 12px" />
        <a-form-item :label="t('inbounds.forwardTargets')" required>
          <a-textarea
            v-model:value="forwardTargetsStr"
            :rows="3"
            style="font-family: monospace; font-size: 12px"
            placeholder="e.g. 198.51.100.10:443&#10;relay.example.com:8443"
          />
        </a-form-item>
      </div>

      <!-- WireGuard Server Inbound Settings -->
      <div v-if="isWireGuard" class="sub-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px">
          <span class="sub-box-title" style="margin-bottom: 0">{{ t('inbounds.wgServerTitle') }}</span>
          <a-button size="small" type="primary" ghost @click="genWgServerKeys">
            🔑 {{ t('routing.wgGenKeys') }}
          </a-button>
        </div>
        <a-alert type="info" show-icon :message="t('routing.wgPlatformNote')" style="margin-bottom: 10px; font-size: 12px" />
        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.wgServerPrivKey')" required>
              <a-input-password v-model:value="form.protocol_settings.wg_server_private_key" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('inbounds.wgServerPubKey')">
              <a-input v-model:value="form.protocol_settings.wg_server_public_key" placeholder="Auto-derived on save" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.wgServerAddrs')" required>
              <a-input v-model:value="wgServerAddrsStr" placeholder="10.77.0.1/32, fd77::1/128" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('inbounds.wgServerDns')">
              <a-input v-model:value="form.protocol_settings.wg_dns" placeholder="1.1.1.1" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('routing.wgMtu')">
              <a-input-number v-model:value="form.protocol_settings.wg_mtu" :min="1280" :max="1420" style="width: 100%" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-row :gutter="12" style="align-items: center; margin-bottom: 10px">
          <a-col :span="8">
            <a-input v-model:value="form.protocol_settings.wg_bind_interface" size="small" :placeholder="t('routing.wgBindInterface')" />
          </a-col>
          <a-col :span="9">
            <a-checkbox v-model:checked="form.protocol_settings.wg_block_private" style="font-size: 12px">
              {{ t('inbounds.wgBlockPrivate') }}
            </a-checkbox>
          </a-col>
          <a-col :span="7">
            <a-checkbox v-model:checked="wgServerHighThroughput" style="font-size: 12px">
              {{ t('routing.wgHighThroughput') }}
            </a-checkbox>
          </a-col>
        </a-row>

        <a-divider orientation="left" style="margin: 8px 0 10px; font-size: 12px">
          Peer 1 ({{ t('inbounds.primaryClient') }})
        </a-divider>
        <a-row :gutter="12">
          <a-col :span="8">
            <a-form-item :label="t('inbounds.clientName')">
              <a-input v-model:value="primaryClient.name" placeholder="phone-1" />
            </a-form-item>
          </a-col>
          <a-col :span="10">
            <a-form-item :label="t('inbounds.wgPeerAllowedIps')">
              <a-input v-model:value="primaryClient.wg_allowed_ips" placeholder="10.77.0.2/32, fd77::2/128" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('inbounds.wgPeerKeepalive')">
              <a-input-number v-model:value="primaryClient.wg_keepalive" :min="0" :max="65535" style="width: 100%" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.wgPeerPrivKey')">
              <a-input-group compact>
                <a-input v-model:value="primaryClient.wg_private_key" style="width: calc(100% - 76px)" />
                <a-button style="width: 76px" @click="genWgPrimaryPeerKeys">🔑 Gen</a-button>
              </a-input-group>
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('routing.wgPsk')">
              <a-input v-model:value="primaryClient.wg_preshared_key" placeholder="Optional Base64 PSK" />
            </a-form-item>
          </a-col>
        </a-row>
      </div>

      <!-- Primary Client Credentials -->
      <template v-if="!isPortForward && !isWireGuard">
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
                <a-select-option value="none">none (Shoes / Xray only)</a-select-option>
              </template>
              <template v-else-if="form.protocol === 'snell'">
                <a-select-option value="aes-128-gcm">aes-128-gcm (Mihomo v3 / Surge)</a-select-option>
                <a-select-option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305 (Mihomo v1 TCP)</a-select-option>
                <a-select-option value="aes-256-gcm">aes-256-gcm (Shoes only)</a-select-option>
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
      </template>

      <!-- VLESS Native Encryption -->
      <div v-if="form.protocol === 'vless'" class="sub-box">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 10px">
          <span class="sub-box-title" style="margin-bottom: 0">{{ t('inbounds.vlessEncTitle') }}</span>
          <a-space size="small" wrap>
            <a-select v-model:value="vlessEncOpts.auth" size="small" style="width: 112px">
              <a-select-option value="mlkem768">ML-KEM-768</a-select-option>
              <a-select-option value="x25519">X25519</a-select-option>
            </a-select>
            <a-select v-model:value="vlessEncOpts.mode" size="small" style="width: 92px">
              <a-select-option value="native">native</a-select-option>
              <a-select-option value="xorpub">xorpub</a-select-option>
              <a-select-option value="random">random</a-select-option>
            </a-select>
            <a-select v-model:value="vlessEncOpts.rtt" size="small" style="width: 72px">
              <a-select-option value="0rtt">0rtt</a-select-option>
              <a-select-option value="1rtt">1rtt</a-select-option>
            </a-select>
            <a-button size="small" type="primary" ghost :loading="vlessEncLoading" @click="genVlessEncKeys">
              🔑 {{ t('inbounds.vlessEncGen') }}
            </a-button>
            <a-button v-if="hasVlessNativeEnc" size="small" danger type="text" @click="clearVlessEnc">
              {{ t('inbounds.vlessEncClear') }}
            </a-button>
          </a-space>
        </div>

        <template v-if="hasVlessNativeEnc">
          <a-alert type="info" show-icon :message="t('inbounds.vlessEncTip')" style="margin-bottom: 10px; font-size: 12px" />
          <a-row :gutter="12">
            <a-col :span="12">
              <a-form-item :label="t('inbounds.vlessDecryption')">
                <a-input v-model:value="form.protocol_settings.vless_decryption" size="small" style="font-family: monospace" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item :label="t('inbounds.vlessEncryption')">
                <a-input v-model:value="form.protocol_settings.vless_encryption" size="small" style="font-family: monospace" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-checkbox
            v-model:checked="form.protocol_settings.vless_native_vision"
            style="margin-bottom: 10px"
            @change="(e) => onNativeVisionToggle(e.target.checked)"
          >
            {{ t('inbounds.vlessNativeVision') }}
          </a-checkbox>
        </template>
      </div>

      <!-- Transport & Security -->
      <template v-if="!isPortForward && !isWireGuard">
      <a-divider orientation="left" style="margin: 8px 0 12px">{{ t('inbounds.transport') }}</a-divider>
      <a-alert
        v-if="!isQuicOuter && ['tls', 'reality', 'shadowtls'].includes(form.stream_settings.security) && !form.stream_settings.sudoku.enabled"
        type="success"
        show-icon
        :message="t('inbounds.sniMuxTip')"
        style="margin-bottom: 10px; font-size: 12px"
      />
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
            <a-select v-model:value="form.stream_settings.security" :disabled="isQuicOuter" @change="onSecurityChange">
              <a-select-option v-if="!requiresTlsOrReality && !isQuicOuter" value="none">None</a-select-option>
              <a-select-option value="tls">TLS</a-select-option>
              <a-select-option v-if="supportsReality && !isQuicOuter" value="reality">REALITY</a-select-option>
              <a-select-option v-if="supportsShadowTls && !isQuicOuter" value="shadowtls">ShadowTLS v3</a-select-option>
            </a-select>
          </a-form-item>
        </a-col>
      </a-row>

      <a-alert
        v-if="compatOmitted.length > 0"
        type="info"
        show-icon
        style="margin-bottom: 12px"
        :message="t('inbounds.compatPartial', { supported: compatSupported.join(' / '), omitted: compatOmitted.join(' / ') })"
      />

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
                <a-select-option v-if="isQuicProtocol" value="auto">{{ t('inbounds.certModeAuto') }}</a-select-option>
                <a-select-option value="source">{{ t('inbounds.certModeSource') }}</a-select-option>
                <a-select-option value="files">{{ t('inbounds.certModeFiles') }}</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col v-if="form.stream_settings.tls.cert_mode === 'source'" :span="8">
            <a-form-item :label="t('inbounds.certSource')" required>
              <a-select v-model:value="form.stream_settings.tls.certificate_source" placeholder="Select certificate" @change="onCertSourceChange">
                <a-select-option v-for="c in certs" :key="c.name" :value="c.name">
                  {{ c.name }} ({{ c.cert_type }})
                </a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col v-if="form.stream_settings.tls.cert_mode !== 'auto'" :span="8">
            <a-form-item :label="t('inbounds.sni')">
              <a-input v-model:value="form.stream_settings.tls.sni" placeholder="proxy.example.com" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-alert v-if="form.stream_settings.tls.cert_mode === 'auto'" type="info" show-icon :message="t('inbounds.autoCertTrust')" />
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
              v-if="form.protocol === 'vless' && form.stream_settings.network === 'tcp' && !isQuicOuter && !hasVlessNativeEnc"
              v-model:checked="form.stream_settings.tls.vision"
              @change="(e) => onVisionToggle(e.target.checked)"
            >
              {{ t('inbounds.vision') }}
            </a-checkbox>
          </a-col>
        </a-row>

        <!-- Post-Quantum TLS Key Exchange & mTLS -->
        <a-row :gutter="12">
          <a-col :span="24">
            <a-form-item :label="t('inbounds.tlsKxGroups')" :extra="t('inbounds.tlsKxTip')">
              <a-select
                v-model:value="form.stream_settings.tls.key_exchange_groups"
                mode="multiple"
                allow-clear
                placeholder="Default (X25519MLKEM768 + classical fallback)"
              >
                <a-select-option value="X25519MLKEM768">X25519MLKEM768 (PQ Hybrid)</a-select-option>
                <a-select-option value="SecP256r1MLKEM768">SecP256r1MLKEM768 (PQ Hybrid)</a-select-option>
                <a-select-option value="X25519">X25519</a-select-option>
                <a-select-option value="SecP256r1">SecP256r1</a-select-option>
                <a-select-option value="SecP384r1">SecP384r1</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>

        <a-collapse ghost style="margin-bottom: 8px">
          <a-collapse-panel key="mtls" :header="`🔐 ${t('inbounds.mtlsTitle')}`">
            <div style="margin-bottom: 8px">
              <a-button size="small" type="dashed" :loading="mtlsGenLoading" @click="genMtlsClientCert">
                ⚡ {{ t('inbounds.mtlsGenClient') }}
              </a-button>
            </div>
            <a-row :gutter="12">
              <a-col :span="12">
                <a-form-item :label="t('inbounds.mtlsCaCerts')">
                  <a-textarea v-model:value="mtlsCaStr" :rows="2" style="font-family: monospace; font-size: 12px" placeholder="/etc/shoes/ca.crt" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item :label="t('inbounds.mtlsFingerprints')">
                  <a-textarea v-model:value="mtlsFpStr" :rows="2" style="font-family: monospace; font-size: 12px" placeholder="AA:BB:CC:..." />
                </a-form-item>
              </a-col>
            </a-row>
          </a-collapse-panel>
        </a-collapse>
      </div>

      <!-- REALITY Settings -->
      <div v-if="!isQuicOuter && form.stream_settings.security === 'reality'" class="sub-box">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 10px">
          <span class="sub-box-title" style="margin-bottom: 0">{{ t('inbounds.realitySettings') }}</span>
          <a-space size="small" wrap>
            <a-button size="small" type="primary" @click="openRealityProbe">
              🔎 {{ t('inbounds.realityProbeBtn') }}
            </a-button>
            <a-button size="small" type="primary" ghost @click="refreshRealityKeys">
              🔑 {{ t('inbounds.genRealityKeys') }}
            </a-button>
            <a-button size="small" :loading="mldsaLoading" @click="genMldsaKeys">
              🛡️ {{ t('inbounds.mldsa65Gen') }}
            </a-button>
          </a-space>
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
              v-if="form.protocol === 'vless' && form.stream_settings.network === 'tcp' && !hasVlessNativeEnc"
              v-model:checked="form.stream_settings.reality.vision"
              @change="(e) => onVisionToggle(e.target.checked)"
            >
              {{ t('inbounds.vision') }}
            </a-checkbox>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.mldsa65Seed')">
              <a-input v-model:value="form.stream_settings.reality.mldsa65_seed" size="small" placeholder="optional 32-byte base64url seed" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('inbounds.mldsa65Verify')">
              <a-input v-model:value="form.stream_settings.reality.mldsa65_verify" size="small" placeholder="optional base64url verify key (pqv)" />
            </a-form-item>
          </a-col>
        </a-row>
        <div v-if="form.stream_settings.reality.mldsa65_seed || form.stream_settings.reality.mldsa65_verify" style="font-size: 11px; opacity: 0.72; margin-bottom: 10px">
          {{ t('inbounds.mldsa65Tip') }}
        </div>
      </div>

      <!-- ShadowTLS v3 Settings -->
      <div v-if="!isQuicOuter && form.stream_settings.security === 'shadowtls'" class="sub-box">
        <div class="sub-box-title">{{ t('inbounds.shadowtlsSettings') }}</div>
        <a-alert type="info" show-icon :message="t('inbounds.shadowtlsTip')" style="margin-bottom: 10px; font-size: 12px" />
        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('inbounds.sni')" required>
              <a-input v-model:value="form.stream_settings.shadowtls.sni" placeholder="www.microsoft.com" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="t('inbounds.shadowtlsPassword')" required>
              <a-input-group compact>
                <a-input v-model:value="form.stream_settings.shadowtls.password" style="width: calc(100% - 92px)" />
                <a-button style="width: 92px" @click="refreshShadowTlsPassword">{{ t('inbounds.genRandom') }}</a-button>
              </a-input-group>
            </a-form-item>
          </a-col>
        </a-row>
        <a-row :gutter="12">
          <a-col :span="10">
            <a-form-item :label="t('inbounds.shadowtlsMode')">
              <a-select v-model:value="form.stream_settings.shadowtls.handshake_mode">
                <a-select-option value="remote">{{ t('inbounds.shadowtlsRemote') }}</a-select-option>
                <a-select-option value="local">{{ t('inbounds.shadowtlsLocal') }}</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col v-if="form.stream_settings.shadowtls.handshake_mode !== 'local'" :span="14">
            <a-form-item :label="t('inbounds.shadowtlsHandshakeAddr')" required>
              <a-input v-model:value="form.stream_settings.shadowtls.handshake_addr" placeholder="www.microsoft.com:443" />
            </a-form-item>
          </a-col>
          <template v-else>
            <a-col :span="7">
              <a-form-item :label="t('inbounds.certFile')" required>
                <a-input v-model:value="form.stream_settings.shadowtls.cert_file" placeholder="/path/to/fullchain.pem" />
              </a-form-item>
            </a-col>
            <a-col :span="7">
              <a-form-item :label="t('inbounds.keyFile')" required>
                <a-input v-model:value="form.stream_settings.shadowtls.key_file" placeholder="/path/to/privkey.pem" />
              </a-form-item>
            </a-col>
          </template>
        </a-row>
      </div>

      <!-- Sudoku TCP FinalMask Obfuscation -->
      <div v-if="!isQuicOuter" class="sub-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px">
          <span class="sub-box-title" style="margin-bottom: 0">{{ t('inbounds.sudokuTitle') }}</span>
          <a-switch v-model:checked="form.stream_settings.sudoku.enabled" size="small" />
        </div>
        <template v-if="form.stream_settings.sudoku.enabled">
          <a-alert type="info" show-icon :message="t('inbounds.sudokuTip')" style="margin-bottom: 10px; font-size: 12px" />
          <a-row :gutter="12">
            <a-col :span="10">
              <a-form-item :label="t('inbounds.sudokuPassword')">
                <a-input v-model:value="form.stream_settings.sudoku.password" placeholder="shared-mask-password" />
              </a-form-item>
            </a-col>
            <a-col :span="7">
              <a-form-item :label="t('inbounds.sudokuAscii')">
                <a-select v-model:value="form.stream_settings.sudoku.ascii">
                  <a-select-option value="">prefer_entropy (default)</a-select-option>
                  <a-select-option value="prefer_entropy">prefer_entropy</a-select-option>
                  <a-select-option value="entropy">entropy</a-select-option>
                  <a-select-option value="prefer_ascii">prefer_ascii</a-select-option>
                  <a-select-option value="ascii">ascii</a-select-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="7">
              <a-form-item :label="t('inbounds.sudokuCustomTable')">
                <a-input v-model:value="form.stream_settings.sudoku.custom_table" placeholder="xpxvvpvv" />
              </a-form-item>
            </a-col>
          </a-row>
          <a-row :gutter="12">
            <a-col :span="12">
              <a-form-item :label="t('inbounds.sudokuPaddingMin')">
                <a-input-number v-model:value="form.stream_settings.sudoku.padding_min" :min="0" :max="100" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item :label="t('inbounds.sudokuPaddingMax')">
                <a-input-number v-model:value="form.stream_settings.sudoku.padding_max" :min="0" :max="100" style="width: 100%" />
              </a-form-item>
            </a-col>
          </a-row>
        </template>
      </div>

      <!-- H2Mux Multiplexing -->
      <div v-if="supportsH2Mux" class="sub-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px">
          <span class="sub-box-title" style="margin-bottom: 0">{{ t('inbounds.h2muxTitle') }}</span>
          <a-switch
            v-model:checked="form.stream_settings.h2mux.enabled"
            size="small"
            @change="onH2MuxToggle"
          />
        </div>
        <template v-if="form.stream_settings.h2mux.enabled">
          <a-alert
            type="info"
            show-icon
            :message="t('inbounds.h2muxTip')"
            style="margin-bottom: 10px; font-size: 12px"
          />
          <a-row :gutter="12">
            <a-col :span="6">
              <a-form-item :label="t('inbounds.h2muxMaxConns')">
                <a-input-number v-model:value="form.stream_settings.h2mux.max_connections" :min="1" :max="64" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="6">
              <a-form-item :label="t('inbounds.h2muxMinStreams')">
                <a-input-number v-model:value="form.stream_settings.h2mux.min_streams" :min="1" :max="256" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="6">
              <a-form-item :label="t('inbounds.h2muxMaxStreams')">
                <a-input-number v-model:value="form.stream_settings.h2mux.max_streams" :min="0" :max="1024" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="6" style="display: flex; align-items: center; padding-top: 16px">
              <a-checkbox v-model:checked="form.stream_settings.h2mux.padding">
                {{ t('inbounds.h2muxPadding') }}
              </a-checkbox>
            </a-col>
          </a-row>
        </template>
      </div>
      </template>

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
            <a-col :span="8">
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
            <a-col :span="8">
              <a-form-item :label="t('inbounds.dnsGroup')">
                <a-select v-model:value="form.protocol_settings.dns_group" allow-clear placeholder="Default (Global DNS)">
                  <a-select-option value="">Default (Global DNS)</a-select-option>
                  <a-select-option value="__system__">System Resolver Only</a-select-option>
                  <a-select-option v-for="dg in dnsGroups" :key="dg.name" :value="dg.name">
                    DNS: {{ dg.name }}
                  </a-select-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="8">
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

  <!-- REALITY Destination Probe & Picker Modal -->
  <a-modal
    v-model:open="realityProbeOpen"
    :title="t('inbounds.realityProbeTitle')"
    width="1020px"
    :footer="null"
  >
    <a-alert
      type="info"
      show-icon
      :message="t('inbounds.realityProbeDesc')"
      style="margin-bottom: 12px; font-size: 12px"
    />
    <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; align-items: center">
      <a-input
        v-model:value="probeDestInput"
        style="flex: 1 1 220px"
        placeholder="Dest (e.g. www.microsoft.com:443)"
        @pressEnter="runRealityProbe(false)"
      />
      <a-input
        v-model:value="probeSniInput"
        style="flex: 1 1 180px"
        placeholder="SNI (optional, defaults to Dest host)"
        @pressEnter="runRealityProbe(false)"
      />
      <a-button type="primary" :loading="realityProbing" @click="runRealityProbe(false)">
        🔎 {{ t('inbounds.realityProbeSingle') }}
      </a-button>
      <a-button :loading="realityProbing" @click="runRealityProbe(true)">
        ⚡ {{ t('inbounds.realityProbeBatch') }}
      </a-button>
    </div>

    <a-table
      :data-source="realityProbeResults"
      :columns="realityProbeColumns"
      :loading="realityProbing"
      :pagination="false"
      size="small"
      row-key="dest"
      :scroll="{ x: 920 }"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'target'">
          <div style="font-weight: 600; font-family: monospace">{{ record.dest }}</div>
          <div style="font-size: 11px; opacity: 0.7">SNI: {{ record.sni }}</div>
        </template>

        <template v-else-if="column.key === 'latency'">
          <template v-if="record.reachable">
            <a-tag :color="(record.tls_ms ?? 999) < 180 ? 'success' : (record.tls_ms ?? 999) < 400 ? 'warning' : 'error'">
              {{ record.tcp_ms ?? '-' }}ms / {{ record.tls_ms ?? '-' }}ms
            </a-tag>
          </template>
          <a-tag v-else color="error">Unreachable</a-tag>
        </template>

        <template v-else-if="column.key === 'proto'">
          <a-space :size="4" wrap>
            <a-tag v-if="record.tls_version" :color="record.tls_version === 'TLSv1.3' ? 'green' : 'error'">
              {{ record.tls_version }}
            </a-tag>
            <a-tag v-if="record.alpn" :color="record.alpn === 'h2' ? 'blue' : 'orange'">
              {{ record.alpn }}
            </a-tag>
            <a-tag v-if="record.x25519" color="cyan">X25519</a-tag>
            <a-tag v-if="record.hello_retry" color="error">HRR</a-tag>
          </a-space>
        </template>

        <template v-else-if="column.key === 'mldsa'">
          <div v-if="record.reachable">
            <a-tag :color="record.mldsa65_compatible ? 'geekblue' : 'default'">
              {{ record.mldsa65_compatible ? 'ML-DSA-65 ✓' : 'Standard Only' }}
            </a-tag>
            <div v-if="record.flight_mode" style="font-size: 11px; opacity: 0.7">
              {{ record.flight_mode }} · {{ record.cert_capacity_bytes }}B
            </div>
          </div>
          <span v-else style="opacity: 0.45">-</span>
        </template>

        <template v-else-if="column.key === 'cert'">
          <template v-if="record.cert_issuer || record.cert_subject">
            <div style="font-size: 11px; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="`${record.cert_subject} / ${record.cert_issuer}`">
              {{ record.cert_issuer || record.cert_subject }}
            </div>
            <div style="font-size: 11px">
              <a-tag v-if="record.sni_matched" color="green" style="font-size: 10px">SAN ✓</a-tag>
              <a-tag v-else color="error" style="font-size: 10px">SAN ✗</a-tag>
              <span v-if="record.cert_days_left != null" style="opacity: 0.7">{{ record.cert_days_left }}d</span>
            </div>
          </template>
          <span v-else style="opacity: 0.45">-</span>
        </template>

        <template v-else-if="column.key === 'verdict'">
          <a-tooltip :title="(record.reasons || []).join(' | ') || (record.error || 'All checks passed')">
            <a-tag
              :color="
                record.verdict === 'excellent'
                  ? 'success'
                  : record.verdict === 'good'
                    ? 'processing'
                    : record.verdict === 'warn'
                      ? 'warning'
                      : 'error'
              "
            >
              {{ (record.verdict || 'fail').toUpperCase() }} ({{ record.score }})
            </a-tag>
          </a-tooltip>
        </template>

        <template v-else-if="column.key === 'action'">
          <a-button
            size="small"
            :type="record.suitable ? 'primary' : 'default'"
            :disabled="!record.reachable"
            @click="applyRealityProbeResult(record)"
          >
            {{ t('inbounds.realityProbeUse') }}
          </a-button>
        </template>
      </template>
    </a-table>
  </a-modal>

  <!-- mTLS Generated Client Cert Preview Modal -->
  <a-modal
    v-model:open="mtlsResultOpen"
    :title="t('inbounds.mtlsClientModalTitle')"
    width="660px"
    :footer="null"
  >
    <a-form layout="vertical">
      <a-form-item label="SHA-256 Fingerprint">
        <a-input :value="mtlsResult.fingerprint" readonly style="font-family: monospace" />
      </a-form-item>
      <a-form-item label="Client Certificate PEM (save as client.crt)">
        <a-textarea :value="mtlsResult.cert_pem" :rows="6" readonly style="font-family: monospace; font-size: 11px" />
      </a-form-item>
      <a-form-item label="Client Private Key PEM (save as client.key)">
        <a-textarea :value="mtlsResult.key_pem" :rows="5" readonly style="font-family: monospace; font-size: 11px" />
      </a-form-item>
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
  dnsGroups: { type: Array, default: () => [] },
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
      dns_group: '',
      vless_decryption: '',
      vless_encryption: '',
      vless_native_vision: false,
      port_range: '',
      forward_targets: [],
      wg_server_private_key: '',
      wg_server_public_key: '',
      wg_server_addresses: ['10.77.0.1/32', 'fd77::1/128'],
      wg_mtu: 1408,
      wg_dns: '1.1.1.1',
      wg_bind_interface: '',
      wg_block_private: true,
      wg_tcp_buffer_size: null,
      wg_tcp_memory_bytes: null,
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
        key_exchange_groups: [],
        client_ca_certs: [],
        client_fingerprints: [],
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
      shadowtls: {
        sni: 'www.microsoft.com',
        password: '',
        handshake_mode: 'remote',
        handshake_addr: 'www.microsoft.com:443',
        cert_file: '',
        key_file: '',
        client_ca_certs: [],
        client_fingerprints: [],
      },
      ws: { path: '/ws', host: '', headers: {}, max_early_data: 0, early_data_header_name: '' },
      xhttp: { path: '/xhttp', host: '', mode: 'auto', headers: {} },
      h2mux: { enabled: false, max_connections: 4, min_streams: 4, max_streams: 0, padding: false },
      sudoku: { enabled: false, password: '', ascii: '', custom_table: '', custom_tables: [], padding_min: 0, padding_max: 0 },
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
        wg_private_key: '',
        wg_public_key: '',
        wg_preshared_key: '',
        wg_allowed_ips: '10.77.0.2/32, fd77::2/128',
        wg_keepalive: 25,
      },
    ],
  };
}

const form = reactive(blankInbound());
const quotaGb = ref(0);
const expiryDayjs = ref(null);
const alpnStr = ref('');
const shortIdsStr = ref('0123456789abcdef');
const forwardTargetsStr = ref('');
const wgServerAddrsStr = ref('10.77.0.1/32, fd77::1/128');
const wgServerHighThroughput = ref(false);
const mtlsCaStr = ref('');
const mtlsFpStr = ref('');
const mtlsGenLoading = ref(false);
const mtlsResultOpen = ref(false);
const mtlsResult = reactive({ cert_pem: '', key_pem: '', fingerprint: '' });
const vlessEncLoading = ref(false);
const mldsaLoading = ref(false);
const vlessEncOpts = reactive({ auth: 'mlkem768', mode: 'native', rtt: '0rtt', lifetime: '600s' });

const primaryClient = computed(() => {
  if (!form.clients || form.clients.length === 0) {
    form.clients = [blankInbound().clients[0]];
  }
  return form.clients[0];
});

const isPortForward = computed(() => form.protocol === 'portforward');
const isWireGuard = computed(() => form.protocol === 'wireguard');
const hasVlessNativeEnc = computed(
  () =>
    form.protocol === 'vless' &&
    Boolean(form.protocol_settings.vless_decryption && form.protocol_settings.vless_decryption.trim() !== 'none')
);
const isQuicProtocol = computed(() => ['hysteria2', 'tuic'].includes(form.protocol));
const isQuicOuter = computed(() => isQuicProtocol.value || form.stream_settings.network === 'quic');
const requiresTlsOrReality = computed(() => ['anytls', 'naiveproxy'].includes(form.protocol));
const supportsReality = computed(() =>
  ['vless', 'trojan', 'anytls', 'naiveproxy', 'vmess', 'shadowsocks'].includes(form.protocol)
);
const supportsShadowTls = computed(() =>
  ['shadowsocks', 'vless', 'vmess', 'trojan', 'socks', 'mixed'].includes(form.protocol)
);
const supportsWs = computed(() =>
  ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks'].includes(form.protocol)
);
const supportsXhttp = computed(() => ['vless', 'vmess', 'trojan', 'shadowsocks'].includes(form.protocol));
const supportsH2Mux = computed(() => {
  const p = form.protocol;
  const net = form.stream_settings.network;
  const sec = form.stream_settings.security;
  if (sec === 'shadowtls') return false;
  if (['vless', 'vmess', 'trojan'].includes(p)) {
    return ['tcp', 'ws'].includes(net);
  }
  if (p === 'shadowsocks') {
    return net === 'tcp' && sec === 'none';
  }
  return false;
});

const needsUuid = computed(() => ['vless', 'vmess', 'tuic'].includes(form.protocol));
const needsPassword = computed(() =>
  ['trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'naiveproxy', 'snell', 'socks', 'http', 'mixed'].includes(
    form.protocol
  )
);
const needsUsername = computed(() => ['naiveproxy', 'socks', 'http', 'mixed'].includes(form.protocol));
const needsCipher = computed(() => ['shadowsocks', 'vmess', 'snell'].includes(form.protocol));

const compatInfo = computed(() => {
  const p = form.protocol;
  const net = isQuicProtocol.value ? 'quic' : form.stream_settings.network;
  const sec = isQuicOuter.value ? 'tls' : form.stream_settings.security;
  const cipher = (form.protocol_settings.cipher || '').trim().toLowerCase();

  if (p === 'portforward') {
    return { supported: ['Shoes'], omitted: [] };
  }
  if (p === 'wireguard') {
    return { supported: ['WireGuard App', 'Shoes', 'Mihomo / Clash', 'sing-box'], omitted: [] };
  }
  if (!isQuicOuter.value && form.stream_settings.sudoku?.enabled) {
    return { supported: ['Shoes'], omitted: ['Mihomo / Clash', 'sing-box'] };
  }

  let mihomo = false;
  let singbox = false;

  if (p === 'vless') {
    mihomo = sec !== 'shadowtls' && ['tcp', 'ws', 'xhttp'].includes(net) && !(net === 'ws' && sec === 'reality');
    singbox = !hasVlessNativeEnc.value && ((sec === 'shadowtls' && net === 'tcp') || (sec !== 'shadowtls' && ['tcp', 'ws', 'quic'].includes(net)));
  } else if (p === 'vmess') {
    const okCipher = cipher !== 'none';
    mihomo = okCipher && sec !== 'shadowtls' && ['tcp', 'ws'].includes(net) && !(net === 'ws' && sec === 'reality');
    singbox = okCipher && ((sec === 'shadowtls' && net === 'tcp') || (sec !== 'shadowtls' && ['tcp', 'ws'].includes(net)));
  } else if (p === 'trojan') {
    mihomo = sec !== 'shadowtls' && ['tcp', 'ws'].includes(net) && sec !== 'none' && !(net === 'ws' && sec === 'reality');
    singbox = (sec === 'shadowtls' && net === 'tcp') || (sec !== 'shadowtls' && ['tcp', 'ws'].includes(net));
  } else if (p === 'shadowsocks') {
    mihomo = (net === 'tcp' && ['none', 'shadowtls'].includes(sec)) || (net === 'ws' && ['none', 'tls'].includes(sec));
    singbox = (net === 'tcp' && ['none', 'shadowtls'].includes(sec)) || (net === 'ws' && sec === 'none')
      || (net === 'ws' && sec === 'tls' && !form.stream_settings.tls.allow_insecure);
  } else if (p === 'hysteria2' || p === 'tuic') {
    mihomo = true;
    singbox = true;
  } else if (p === 'anytls') {
    mihomo = net === 'tcp' && sec === 'tls';
    singbox = net === 'tcp' && ['tls', 'reality'].includes(sec);
  } else if (p === 'naiveproxy') {
    mihomo = false;
    singbox = net === 'tcp' && sec === 'tls';
  } else if (p === 'snell') {
    const effCipher = cipher || 'aes-128-gcm';
    mihomo = net === 'tcp' && sec === 'none' && ['aes-128-gcm', 'chacha20-ietf-poly1305'].includes(effCipher);
    singbox = false;
  } else if (p === 'socks') {
    mihomo = net === 'tcp' && sec !== 'shadowtls';
    singbox = net === 'tcp' && sec === 'none';
  } else if (p === 'http' || p === 'mixed') {
    mihomo = net === 'tcp' && sec !== 'shadowtls';
    singbox = net === 'tcp' && sec !== 'shadowtls';
  }

  const supported = ['Shoes'];
  const omitted = [];
  if (mihomo) supported.push('Mihomo / Clash');
  else omitted.push('Mihomo / Clash');
  if (singbox) supported.push('sing-box');
  else omitted.push('sing-box');
  return { supported, omitted };
});
const compatSupported = computed(() => compatInfo.value.supported);
const compatOmitted = computed(() => compatInfo.value.omitted);

watch(
  () => props.open,
  async (val) => {
    if (!val) return;
    if (props.record && props.record.id > 0) {
      const cloned = JSON.parse(JSON.stringify(props.record));
      const blank = blankInbound();
      Object.assign(form, blank, cloned);
      form.protocol_settings = Object.assign(
        {},
        blank.protocol_settings,
        cloned.protocol_settings || {}
      );
      form.stream_settings.tls = Object.assign(
        {},
        blank.stream_settings.tls,
        cloned.stream_settings?.tls || {}
      );
      form.stream_settings.h2mux = Object.assign(
        {},
        blank.stream_settings.h2mux,
        cloned.stream_settings?.h2mux || {}
      );
      form.stream_settings.shadowtls = Object.assign(
        {},
        blank.stream_settings.shadowtls,
        cloned.stream_settings?.shadowtls || {}
      );
      form.stream_settings.sudoku = Object.assign(
        {},
        blank.stream_settings.sudoku,
        cloned.stream_settings?.sudoku || {}
      );
      if (isQuicProtocol.value) selectAutoCertIfEmpty();
      quotaGb.value = form.total_quota_bytes / 1073741824;
      expiryDayjs.value = form.expiry_time > 0 ? dayjs(form.expiry_time) : null;
      alpnStr.value = (form.stream_settings.tls.alpn || []).join(',');
      shortIdsStr.value = (form.stream_settings.reality.short_ids || []).join(',');
      forwardTargetsStr.value = (form.protocol_settings.forward_targets || []).join('\n');
      wgServerAddrsStr.value = (form.protocol_settings.wg_server_addresses?.length
        ? form.protocol_settings.wg_server_addresses
        : ['10.77.0.1/32', 'fd77::1/128']
      ).join(', ');
      wgServerHighThroughput.value = Boolean(
        form.protocol_settings.wg_tcp_buffer_size && form.protocol_settings.wg_tcp_buffer_size >= 262144
      );
      mtlsCaStr.value = (form.stream_settings.tls.client_ca_certs || []).join('\n');
      mtlsFpStr.value = (form.stream_settings.tls.client_fingerprints || []).join('\n');
    } else {
      Object.assign(form, blankInbound());
      quotaGb.value = 0;
      expiryDayjs.value = null;
      alpnStr.value = '';
      shortIdsStr.value = '0123456789abcdef';
      forwardTargetsStr.value = '';
      wgServerAddrsStr.value = '10.77.0.1/32, fd77::1/128';
      wgServerHighThroughput.value = false;
      mtlsCaStr.value = '';
      mtlsFpStr.value = '';
      if (props.certs?.length > 0) {
        form.stream_settings.tls.certificate_source = props.certs[0].name;
        onCertSourceChange(props.certs[0].name);
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

function selectAutoCertIfEmpty() {
  const tls = form.stream_settings.tls;
  if (tls.cert_mode === 'source' && !tls.certificate_source && !tls.cert_file && !tls.key_file) {
    tls.cert_mode = 'auto';
  }
}

async function onProtocolChange(proto) {
  form.remark = `${proto.toUpperCase()}-${form.port}`;
  if (['hysteria2', 'tuic'].includes(proto)) {
    selectAutoCertIfEmpty();
    form.stream_settings.network = 'quic';
    form.stream_settings.security = 'tls';
  } else {
    if (form.stream_settings.tls.cert_mode === 'auto') form.stream_settings.tls.cert_mode = 'source';
    const network = form.stream_settings.network;
    if (network === 'quic' || (network === 'ws' && !supportsWs.value) || (network === 'xhttp' && !supportsXhttp.value)) {
      form.stream_settings.network = 'tcp';
    }
    if (proto === 'vless') {
      form.stream_settings.security = 'reality';
    } else if (['trojan', 'anytls', 'naiveproxy'].includes(proto)) {
      form.stream_settings.security = 'tls';
      if (proto === 'naiveproxy' && !alpnStr.value) alpnStr.value = 'h2,http/1.1';
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
    form.protocol_settings.cipher = 'aes-128-gcm';
  } else if (proto === 'wireguard') {
    form.stream_settings.network = 'tcp';
    form.stream_settings.security = 'none';
    form.stream_settings.sudoku.enabled = false;
    form.stream_settings.h2mux.enabled = false;
    if (!form.protocol_settings.wg_server_private_key) {
      await genWgServerKeys();
    }
    if (!primaryClient.value.wg_private_key) {
      await genWgPrimaryPeerKeys();
    }
  } else if (['socks', 'http', 'mixed'].includes(proto) && !isEdit.value) {
    primaryClient.value.username = '';
    primaryClient.value.password = '';
  }
  if (!supportsH2Mux.value) {
    form.stream_settings.h2mux.enabled = false;
  }
}

async function genWgServerKeys() {
  try {
    const res = await api.genWireguard();
    form.protocol_settings.wg_server_private_key = res.private_key;
    form.protocol_settings.wg_server_public_key = res.public_key;
  } catch (e) {
    message.error(e.message);
  }
}

async function genWgPrimaryPeerKeys() {
  try {
    const res = await api.genWireguard();
    primaryClient.value.wg_private_key = res.private_key;
    primaryClient.value.wg_public_key = res.public_key;
    primaryClient.value.wg_preshared_key = res.preshared_key || '';
    if (!primaryClient.value.wg_allowed_ips) {
      primaryClient.value.wg_allowed_ips = '10.77.0.2/32, fd77::2/128';
    }
  } catch (e) {
    message.error(e.message);
  }
}

async function genMtlsClientCert() {
  mtlsGenLoading.value = true;
  try {
    const res = await api.genMtlsClient(form.remark || 'shoes-client');
    mtlsResult.cert_pem = res.cert_pem;
    mtlsResult.key_pem = res.key_pem;
    mtlsResult.fingerprint = res.fingerprint;
    const existing = mtlsFpStr.value.trim();
    mtlsFpStr.value = existing ? `${existing}\n${res.fingerprint}` : res.fingerprint;
    mtlsResultOpen.value = true;
  } catch (e) {
    message.error(e.message);
  } finally {
    mtlsGenLoading.value = false;
  }
}

function onNetworkChange(net) {
  if (net === 'quic') {
    form.stream_settings.security = 'tls';
    form.stream_settings.h2mux.enabled = false;
  } else if (net === 'xhttp') {
    form.stream_settings.h2mux.enabled = false;
  }
}

function onH2MuxToggle(enabled) {
  if (enabled) {
    // VLESS Vision is mutually exclusive with H2Mux across Shoes, Mihomo, and sing-box.
    form.stream_settings.tls.vision = false;
    form.stream_settings.reality.vision = false;
    form.protocol_settings.vless_native_vision = false;
  }
}

function onVisionToggle(enabled) {
  if (enabled) {
    form.stream_settings.h2mux.enabled = false;
  }
}

function onNativeVisionToggle(enabled) {
  if (enabled) {
    form.stream_settings.h2mux.enabled = false;
    form.stream_settings.tls.vision = false;
    form.stream_settings.reality.vision = false;
  }
}

async function onSecurityChange(sec) {
  if (sec === 'shadowtls') {
    form.stream_settings.h2mux.enabled = false;
    if (!form.stream_settings.shadowtls.password) {
      await refreshShadowTlsPassword();
    }
  }
}

async function genVlessEncKeys() {
  vlessEncLoading.value = true;
  try {
    const res = await api.genVlessEncryption(vlessEncOpts);
    form.protocol_settings.vless_decryption = res.decryption;
    form.protocol_settings.vless_encryption = res.encryption;
    form.protocol_settings.fallback = '';
    form.stream_settings.tls.vision = false;
    form.stream_settings.reality.vision = false;
    message.success('Generated VLESS native encryption credentials');
  } catch (e) {
    message.error(e.message);
  } finally {
    vlessEncLoading.value = false;
  }
}

function clearVlessEnc() {
  form.protocol_settings.vless_decryption = '';
  form.protocol_settings.vless_encryption = '';
  form.protocol_settings.vless_native_vision = false;
}

async function genMldsaKeys() {
  mldsaLoading.value = true;
  try {
    const res = await api.genMldsa65();
    form.stream_settings.reality.mldsa65_seed = res.mldsa65_seed;
    form.stream_settings.reality.mldsa65_verify = res.mldsa65_verify;
    message.success('Generated ML-DSA-65 post-quantum keys');
  } catch (e) {
    message.error(e.message);
  } finally {
    mldsaLoading.value = false;
  }
}

async function refreshShadowTlsPassword() {
  try {
    const { secret } = await api.genRandom(24);
    form.stream_settings.shadowtls.password = secret;
  } catch {}
}

function onCertSourceChange(certName) {
  const matched = (props.certs || []).find((c) => c.name === certName);
  if (!matched) return;
  if (matched.cert_type === 'acme') {
    form.stream_settings.tls.allow_insecure = false;
    if (!form.stream_settings.tls.sni && matched.domains?.length > 0) {
      form.stream_settings.tls.sni = matched.domains[0];
    }
  } else if (matched.cert_type === 'acme_ip') {
    form.stream_settings.tls.allow_insecure = false;
    // RFC 6066: IP certificates are verified by IP SAN without a hostname SNI
    form.stream_settings.tls.sni = '';
  } else if (
    matched.runtime?.is_self_signed ||
    (matched.remark || '').toLowerCase().includes('self') ||
    certName.toLowerCase().startsWith('self')
  ) {
    form.stream_settings.tls.allow_insecure = true;
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

const realityProbeOpen = ref(false);
const realityProbing = ref(false);
const probeDestInput = ref('');
const probeSniInput = ref('');
const realityProbeResults = ref([]);

const realityProbeColumns = computed(() => [
  { title: t('inbounds.realityProbeTarget'), key: 'target', width: 190 },
  { title: t('inbounds.realityProbeLatency'), key: 'latency', width: 115 },
  { title: t('inbounds.realityProbeProto'), key: 'proto', width: 165 },
  { title: t('inbounds.realityProbeMldsa'), key: 'mldsa', width: 125 },
  { title: t('inbounds.realityProbeCert'), key: 'cert', width: 150 },
  { title: t('inbounds.realityProbeVerdict'), key: 'verdict', width: 110 },
  { title: t('app.actions'), key: 'action', width: 95, fixed: 'right' },
]);

function openRealityProbe() {
  probeDestInput.value = form.stream_settings.reality.dest || 'www.microsoft.com:443';
  probeSniInput.value = form.stream_settings.reality.sni || '';
  realityProbeOpen.value = true;
  if (probeDestInput.value.trim()) {
    runRealityProbe(false);
  }
}

async function runRealityProbe(usePresets) {
  realityProbing.value = true;
  try {
    const res = await api.probeReality({
      dest: probeDestInput.value.trim(),
      sni: probeSniInput.value.trim(),
      use_presets: Boolean(usePresets),
      timeout_ms: 4500,
    });
    realityProbeResults.value = res.results || [];
  } catch (e) {
    message.error(e.message);
  } finally {
    realityProbing.value = false;
  }
}

function applyRealityProbeResult(rec) {
  form.stream_settings.reality.dest = rec.dest;
  form.stream_settings.reality.sni = rec.sni;
  realityProbeOpen.value = false;
  message.success(t('inbounds.realityProbeApplied', { dest: rec.dest, sni: rec.sni }));
}

async function quickGenSelfSigned() {
  try {
    const sni = form.stream_settings.tls.sni?.trim();
    const domains = [];
    if (sni) domains.push(sni);
    try {
      const s = await api.getSettings();
      const ph = s?.settings?.public_host?.trim();
      const dip = s?.detected_public_ip?.trim();
      if (ph && !domains.includes(ph)) domains.push(ph);
      if (dip && !domains.includes(dip)) domains.push(dip);
    } catch {}
    if (!domains.includes('localhost')) domains.push('localhost');
    if (!domains.includes('127.0.0.1')) domains.push('127.0.0.1');
    const primaryLabel = domains[0] || 'localhost';
    const name = `selfsigned-${Date.now().toString().slice(-5)}`;
    const cert = await api.selfSignedCert({
      name,
      domains,
      remark: `Auto Self-Signed (${primaryLabel})`,
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
    payload.stream_settings.tls.client_ca_certs = mtlsCaStr.value
      .split(/[\n,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    payload.stream_settings.tls.client_fingerprints = mtlsFpStr.value
      .split(/[\n,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    payload.stream_settings.reality.short_ids = shortIdsStr.value
      .split(',')
      .map((s) => s.trim());
    payload.protocol_settings.forward_targets = forwardTargetsStr.value
      .split(/[\n,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    payload.protocol_settings.wg_server_addresses = wgServerAddrsStr.value
      .split(/[\n,;\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    payload.protocol_settings.wg_tcp_buffer_size = wgServerHighThroughput.value ? 262144 : null;
    payload.protocol_settings.wg_tcp_memory_bytes = wgServerHighThroughput.value ? 268435456 : null;
    if (payload.protocol === 'portforward') {
      payload.stream_settings.network = 'tcp';
      payload.stream_settings.security = 'none';
      payload.stream_settings.h2mux.enabled = false;
      payload.stream_settings.sudoku.enabled = false;
    } else if (payload.protocol === 'wireguard') {
      payload.stream_settings.network = 'tcp';
      payload.stream_settings.security = 'none';
      payload.stream_settings.h2mux.enabled = false;
      payload.stream_settings.sudoku.enabled = false;
    }

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
