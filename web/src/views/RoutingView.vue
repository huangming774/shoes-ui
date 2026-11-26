<template>
  <a-card size="small">
    <a-tabs v-model:activeKey="activeTab" @change="onTabChange">
      <!-- Tab 1: Outbound Groups (including WireGuard / WARP) + Live Clash Selector -->
      <a-tab-pane key="outbounds" :tab="t('routing.outboundsTab')">
        <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 12px">
          <a-space wrap>
            <a-button type="primary" @click="openNewGroup">+ {{ t('routing.addGroup') }}</a-button>
            <a-button :loading="warpBusy" @click="openQuickWarpGroup">
              ⚡ {{ t('routing.quickWarpBtn') }}
            </a-button>
            <a-button @click="loadAll">↻ {{ t('app.refresh') }}</a-button>
          </a-space>
        </div>

        <a-table :data-source="groups" :columns="groupColumns" row-key="id" size="small" :pagination="false">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'enable'">
              <a-badge :status="record.enable ? 'success' : 'default'" :text="record.enable ? 'ON' : 'OFF'" />
            </template>
            <template v-else-if="column.key === 'group_type'">
              <a-tag color="purple">{{ record.group_type }}</a-tag>
            </template>
            <template v-else-if="column.key === 'members'">
              <span v-if="record.raw_chains_yaml">Custom YAML</span>
              <a-space v-else wrap :size="4">
                <a-tag
                  v-for="(m, i) in record.members"
                  :key="i"
                  :color="memberTagColor(m)"
                >
                  {{ formatMemberSummary(m) }}
                </a-tag>
              </a-space>
            </template>
            <template v-else-if="column.key === 'actions'">
              <a-space size="small">
                <a-button size="small" type="primary" ghost @click="probeOutboundUnlock(record)">
                  🔍 {{ t('routing.egressProbeBtn') }}
                </a-button>
                <a-button size="small" @click="openEditGroup(record)">{{ t('app.edit') }}</a-button>
                <a-popconfirm :title="t('app.deleteConfirm')" @confirm="delGroup(record)">
                  <a-button size="small" danger>{{ t('app.delete') }}</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>

        <!-- Live Clash Controller Selector Box -->
        <a-divider orientation="left" style="margin-top: 22px">{{ t('routing.liveSelector') }}</a-divider>
        <div v-if="liveGroups.length === 0" style="opacity: 0.65; font-size: 13px; padding: 8px 0">
          No active Selector / URL-Test groups reported by shoes Clash API yet.
        </div>
        <a-row v-else :gutter="[12, 12]">
          <a-col v-for="lg in liveGroups" :key="lg.name" :xs="24" :md="12">
            <a-card size="small" :title="`${lg.name} (${lg.type})`">
              <template #extra>
                <a-button size="small" :loading="probing === lg.name" @click="probeGroup(lg.name)">
                  ⚡ {{ t('routing.probeDelay') }}
                </a-button>
              </template>
              <a-space wrap>
                <a-tag
                  v-for="m in lg.all || []"
                  :key="m"
                  :color="lg.now === m ? 'blue' : 'default'"
                  style="cursor: pointer; padding: 4px 10px"
                  @click="lg.type === 'Selector' && selectMember(lg.name, m)"
                >
                  {{ lg.now === m ? '● ' : '' }}{{ m }}
                  <span v-if="delays[m]" style="opacity: 0.75"> ({{ delays[m] }}ms)</span>
                </a-tag>
              </a-space>
            </a-card>
          </a-col>
        </a-row>
      </a-tab-pane>

      <!-- Tab 2: Rule Source Groups (GeoIP / GeoSite / SRS / MRS / YAML) -->
      <a-tab-pane key="rule_sources" :tab="t('routing.ruleSourcesTab')">
        <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 10px">
          <a-space wrap>
            <a-button type="primary" @click="openNewRuleSource">+ {{ t('routing.addRuleSource') }}</a-button>
            <a-button @click="loadAll">↻ {{ t('app.refresh') }}</a-button>
          </a-space>
        </div>

        <div style="margin-bottom: 12px; display: flex; flex-wrap: wrap; align-items: center; gap: 6px">
          <span style="font-size: 12px; opacity: 0.75">{{ t('routing.ruleSourcePresets') }}:</span>
          <a-tag
            v-for="preset in RULE_SOURCE_PRESETS"
            :key="preset.name"
            color="geekblue"
            style="cursor: pointer"
            @click="openRuleSourcePreset(preset)"
          >
            + {{ preset.label }}
          </a-tag>
        </div>

        <a-table :data-source="ruleSources" :columns="ruleSourceColumns" row-key="id" size="small" :pagination="false">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'enable'">
              <a-badge :status="record.enable ? 'success' : 'default'" :text="record.enable ? 'ON' : 'OFF'" />
            </template>
            <template v-else-if="column.key === 'sources'">
              <div v-for="(item, i) in record.items || []" :key="i" style="font-size: 12px">
                <a-tag size="small" :color="item.source_type === 'url' ? 'blue' : 'default'">
                  {{ item.source_type === 'url' ? (item.sync_mode === 'shoes_native' ? 'URL (Native)' : 'URL (Auto)') : 'LOCAL' }}
                </a-tag>
                <code>{{ item.source_type === 'url' ? item.url : item.path }}</code>
                <a-tag v-if="item.format && item.format !== 'auto'" size="small">{{ item.format }}</a-tag>
                <a-tag v-if="item.code" size="small" color="purple">{{ item.code }}</a-tag>
              </div>
            </template>
            <template v-else-if="column.key === 'status'">
              <div v-for="(item, i) in record.items || []" :key="i" style="font-size: 12px">
                <span v-if="item.last_error" style="color: #ff4d4f">{{ item.last_error }}</span>
                <span v-else-if="item.file_size > 0" style="color: #52c41a">
                  {{ formatBytes(item.file_size) }} · {{ formatTimestamp(item.last_updated_at) }}
                </span>
                <span v-else style="opacity: 0.65">{{ item.sync_mode === 'shoes_native' ? 'Shoes Native' : '-' }}</span>
              </div>
            </template>
            <template v-else-if="column.key === 'actions'">
              <a-space size="small">
                <a-button
                  size="small"
                  :loading="syncingRuleSourceId === record.id"
                  @click="syncRuleSourceNow(record)"
                >
                  ↻ {{ t('routing.syncNow') }}
                </a-button>
                <a-button size="small" @click="openEditRuleSource(record)">{{ t('app.edit') }}</a-button>
                <a-popconfirm :title="t('app.deleteConfirm')" @confirm="delRuleSource(record)">
                  <a-button size="small" danger>{{ t('app.delete') }}</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- Tab 3: Routing Rules -->
      <a-tab-pane key="rules" :tab="t('routing.rulesTab')">
        <div style="margin-bottom: 10px">
          <a-space wrap>
            <a-button type="primary" @click="openNewRule">+ {{ t('routing.addRule') }}</a-button>
            <a-button @click="loadAll">↻ {{ t('app.refresh') }}</a-button>
          </a-space>
        </div>

        <div style="margin-bottom: 12px; display: flex; flex-wrap: wrap; align-items: center; gap: 6px">
          <span style="font-size: 12px; opacity: 0.75">{{ t('routing.quickRuleTemplates') }}:</span>
          <a-tag color="orange" style="cursor: pointer" @click="openQuickRuleTemplate('openai_warp')">
            + ChatGPT / OpenAI → WARP
          </a-tag>
          <a-tag color="orange" style="cursor: pointer" @click="openQuickRuleTemplate('netflix_warp')">
            + Netflix → WARP
          </a-tag>
          <a-tag color="red" style="cursor: pointer" @click="openQuickRuleTemplate('block_private')">
            + Block Private LAN
          </a-tag>
          <a-tag color="red" style="cursor: pointer" @click="openQuickRuleTemplate('block_cn')">
            + Block CN (GeoIP/GeoSite)
          </a-tag>
          <a-tag color="red" style="cursor: pointer" @click="openQuickRuleTemplate('block_ads')">
            + Block Ads
          </a-tag>
        </div>

        <a-table :data-source="rules" :columns="ruleColumns" row-key="id" size="small" :pagination="false">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'enable'">
              <a-badge :status="record.enable ? 'success' : 'default'" :text="record.enable ? 'ON' : 'OFF'" />
            </template>
            <template v-else-if="column.key === 'match_type'">
              <a-tag :color="record.match_type === 'rule_source_group' ? 'cyan' : 'default'">
                {{ record.match_type }}
              </a-tag>
              <a-tag v-if="record.no_resolve" size="small" color="gold">no_resolve</a-tag>
            </template>
            <template v-else-if="column.key === 'action'">
              <a-tag :color="record.action === 'block' ? 'error' : 'success'">
                {{ record.action.toUpperCase() }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'outbound'">
              <a-tag color="geekblue">{{ record.action === 'block' ? '-' : record.outbound }}</a-tag>
              <div v-if="record.override_address" style="font-size: 11px; opacity: 0.75">
                → {{ record.override_address }}
              </div>
            </template>
            <template v-else-if="column.key === 'actions'">
              <a-space>
                <a-button size="small" @click="openEditRule(record)">{{ t('app.edit') }}</a-button>
                <a-popconfirm :title="t('app.deleteConfirm')" @confirm="delRule(record)">
                  <a-button size="small" danger>{{ t('app.delete') }}</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- Tab 4: DNS Groups, Global IPv4/IPv6 Strategy & Static Hosts -->
      <a-tab-pane key="dns" :tab="t('routing.dnsTab')">
        <a-card size="small" :title="t('routing.defaultDnsSection')" style="margin-bottom: 16px">
          <a-form layout="vertical">
            <a-row :gutter="12">
              <a-col :xs="24" :md="12">
                <a-form-item :label="t('routing.defaultDnsGroup')">
                  <a-select v-model:value="defaultDnsForm.default_dns_group" allow-clear placeholder="System / Quick Strategy">
                    <a-select-option value="">(None — Use Quick Strategy / System DNS)</a-select-option>
                    <a-select-option v-for="dg in dnsGroups.filter((g) => g.enable)" :key="dg.name" :value="dg.name">
                      {{ dg.name }}
                    </a-select-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :xs="24" :md="12">
                <a-form-item :label="t('routing.quickIpStrategy')">
                  <a-select
                    v-model:value="defaultDnsForm.default_dns_ip_strategy"
                    :disabled="Boolean(defaultDnsForm.default_dns_group)"
                  >
                    <a-select-option value="">Default (ipv4_then_ipv6)</a-select-option>
                    <a-select-option value="ipv4_only">IPv4 Only (ipv4_only)</a-select-option>
                    <a-select-option value="ipv4_then_ipv6">IPv4 First (ipv4_then_ipv6)</a-select-option>
                    <a-select-option value="ipv6_then_ipv4">IPv6 First (ipv6_then_ipv4)</a-select-option>
                    <a-select-option value="ipv6_only">IPv6 Only (ipv6_only)</a-select-option>
                    <a-select-option value="ipv4_and_ipv6">Dual Stack Parallel (ipv4_and_ipv6)</a-select-option>
                  </a-select>
                </a-form-item>
              </a-col>
            </a-row>

            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px">
              <b>{{ t('routing.globalHosts') }}</b>
              <a-button size="small" type="dashed" @click="defaultDnsForm.hostsRows.push({ host: '', ips: '' })">
                + {{ t('routing.addHostRow') }}
              </a-button>
            </div>
            <div v-for="(hr, idx) in defaultDnsForm.hostsRows" :key="idx" style="margin-bottom: 6px">
              <a-row :gutter="8">
                <a-col :span="10">
                  <a-input v-model:value="hr.host" size="small" placeholder="e.g. www.netflix.com" />
                </a-col>
                <a-col :span="12">
                  <a-input v-model:value="hr.ips" size="small" placeholder="e.g. 203.0.113.10, 203.0.113.11" />
                </a-col>
                <a-col :span="2" style="text-align: right">
                  <a-button size="small" danger type="text" @click="defaultDnsForm.hostsRows.splice(idx, 1)">✕</a-button>
                </a-col>
              </a-row>
            </div>
          </a-form>

          <a-button type="primary" :loading="savingDefaultDns" style="margin-top: 8px" @click="saveDefaultDns">
            {{ t('app.save') }}
          </a-button>
        </a-card>

        <a-card size="small" :title="t('routing.dnsGroupsSection')">
          <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 10px">
            <a-space wrap>
              <a-button type="primary" @click="openNewDnsGroup">+ {{ t('routing.addDnsGroup') }}</a-button>
              <a-button @click="loadAll">↻ {{ t('app.refresh') }}</a-button>
            </a-space>
          </div>

          <div style="margin-bottom: 12px; display: flex; flex-wrap: wrap; align-items: center; gap: 6px">
            <span style="font-size: 12px; opacity: 0.75">{{ t('routing.dnsPresets') }}:</span>
            <a-tag
              v-for="preset in DNS_PRESETS"
              :key="preset.name"
              color="cyan"
              style="cursor: pointer"
              @click="openDnsPreset(preset)"
            >
              + {{ preset.label }}
            </a-tag>
          </div>

          <a-table :data-source="dnsGroups" :columns="dnsGroupColumns" row-key="id" size="small" :pagination="false">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'enable'">
                <a-badge :status="record.enable ? 'success' : 'default'" :text="record.enable ? 'ON' : 'OFF'" />
              </template>
              <template v-else-if="column.key === 'name'">
                <code>{{ record.name }}</code>
                <a-tag v-if="defaultDnsForm.default_dns_group === record.name" color="green" style="margin-left: 6px">
                  {{ t('routing.isDefaultDns') }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'servers'">
                <a-space wrap :size="4">
                  <a-tag v-for="(s, i) in record.servers || []" :key="i">
                    {{ s.url }}{{ s.ip_strategy ? ` · ${s.ip_strategy}` : '' }}{{ s.client_chain ? ` via ${s.client_chain}` : '' }}
                  </a-tag>
                </a-space>
              </template>
              <template v-else-if="column.key === 'hosts'">
                <span>{{ Object.keys(record.hosts || {}).length }} host(s)</span>
              </template>
              <template v-else-if="column.key === 'actions'">
                <a-space size="small">
                  <a-button
                    v-if="record.enable && defaultDnsForm.default_dns_group !== record.name"
                    size="small"
                    @click="setDefaultDnsGroup(record.name)"
                  >
                    {{ t('routing.setAsDefaultDns') }}
                  </a-button>
                  <a-button size="small" @click="openEditDnsGroup(record)">{{ t('app.edit') }}</a-button>
                  <a-popconfirm :title="t('app.deleteConfirm')" @confirm="delDnsGroup(record)">
                    <a-button size="small" danger>{{ t('app.delete') }}</a-button>
                  </a-popconfirm>
                </a-space>
              </template>
            </template>
          </a-table>
        </a-card>
      </a-tab-pane>

      <!-- Tab 5: VPS Egress Quality & Streaming / AI Unlock Diagnostics -->
      <a-tab-pane key="egress" :tab="`🔍 ${t('routing.egressTab')}`">
        <a-alert
          type="info"
          show-icon
          :message="t('routing.egressTip')"
          style="margin-bottom: 14px; font-size: 12px"
        />

        <a-card size="small" style="margin-bottom: 14px">
          <div style="display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between">
            <a-space wrap align="center">
              <a-checkbox v-model:checked="egressOpts.includeDirectV4">Direct (IPv4)</a-checkbox>
              <a-checkbox v-model:checked="egressOpts.includeDirectV6">Direct (IPv6)</a-checkbox>
              <a-select
                v-model:value="egressOpts.selectedGroups"
                mode="multiple"
                allow-clear
                style="min-width: 240px"
                :placeholder="t('routing.egressSelectGroups')"
              >
                <a-select-option v-for="g in groups" :key="g.name" :value="g.name">
                  {{ g.name }}{{ g.enable ? '' : ' (OFF)' }}
                </a-select-option>
              </a-select>
              <a-select
                v-if="egressOpts.selectedGroups.length > 0"
                v-model:value="egressOpts.groupIpVersion"
                style="width: 135px"
              >
                <a-select-option value="auto">{{ t('routing.egressIpAuto') }}</a-select-option>
                <a-select-option value="ipv4">IPv4 Only</a-select-option>
                <a-select-option value="ipv6">IPv6 Only</a-select-option>
              </a-select>
            </a-space>

            <a-space wrap>
              <a-button type="primary" :loading="egressProbing" @click="runEgressProbe(false)">
                🔍 {{ t('routing.egressRunBtn') }}
              </a-button>
              <a-button :loading="egressProbing" @click="runEgressProbe(true)">
                ⚡ {{ t('routing.egressCompareAllBtn') }}
              </a-button>
              <a-button v-if="!hasWarpGroup" type="dashed" :loading="warpBusy" @click="openQuickWarpGroup">
                ⚡ {{ t('routing.quickWarpBtn') }}
              </a-button>
            </a-space>
          </div>
        </a-card>

        <div v-if="egressProbing && !egressReport" style="padding: 36px 0; text-align: center">
          <a-spin size="large" :tip="t('routing.egressRunningTip')" />
        </div>

        <a-empty v-else-if="!egressReport" :description="t('routing.egressEmptyTip')" style="padding: 28px 0" />

        <template v-else>
          <!-- Closed-Loop Routing Recommendations Banner -->
          <a-alert
            v-if="(egressReport.recommendations || []).length > 0"
            type="success"
            show-icon
            style="margin-bottom: 14px"
            :message="t('routing.egressRecTitle')"
          >
            <template #description>
              <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 6px">
                <a-button
                  v-for="rec in egressReport.recommendations"
                  :key="`${rec.service}-${rec.best_group}`"
                  size="small"
                  type="primary"
                  ghost
                  @click="openRuleFromUnlock(rec.service, rec.best_group, rec.suggested_rule_source, rec.suggested_domains)"
                >
                  ➕ {{ t('routing.egressRouteVia', { service: rec.service_name, group: rec.best_group }) }}
                  <span v-if="rec.best_region" style="opacity: 0.8"> ({{ rec.best_region }})</span>
                </a-button>
              </div>
            </template>
          </a-alert>

          <a-alert
            v-else-if="directHasBlockedServices && !hasWarpGroup"
            type="warning"
            show-icon
            style="margin-bottom: 14px"
            :message="t('routing.egressWarpSuggest')"
          >
            <template #action>
              <a-button size="small" type="primary" :loading="warpBusy" @click="openQuickWarpGroup">
                ⚡ {{ t('routing.quickWarpBtn') }}
              </a-button>
            </template>
          </a-alert>

          <!-- Egress IP & Network Quality Summary Cards -->
          <a-row :gutter="[12, 12]" style="margin-bottom: 14px">
            <a-col
              v-for="rep in egressReport.reports || []"
              :key="rep.target_id"
              :xs="24"
              :md="(egressReport.reports || []).length === 1 ? 24 : 12"
              :lg="(egressReport.reports || []).length >= 3 ? 8 : 12"
            >
              <a-card size="small" style="height: 100%">
                <template #title>
                  <a-space size="small">
                    <a-badge :status="rep.ok ? 'success' : 'error'" />
                    <span>{{ rep.label }}</span>
                    <a-tag
                      v-if="rep.ip_info?.warp_status === 'on' || rep.ip_info?.warp_status === 'plus'"
                      :color="rep.ip_info.warp_status === 'plus' ? 'purple' : 'orange'"
                    >
                      WARP {{ rep.ip_info.warp_status.toUpperCase() }}
                    </a-tag>
                  </a-space>
                </template>
                <template #extra>
                  <span style="font-size: 11px; opacity: 0.65">{{ rep.elapsed_ms }}ms</span>
                </template>

                <a-alert
                  v-if="!rep.ok && rep.error"
                  type="error"
                  show-icon
                  :message="rep.error"
                  style="font-size: 12px"
                />
                <div v-else style="font-size: 12px; display: flex; flex-direction: column; gap: 5px">
                  <div>
                    <span style="opacity: 0.65">IPv4: </span>
                    <code v-if="rep.ip_info?.ipv4">{{ rep.ip_info.ipv4 }}</code>
                    <span v-else style="opacity: 0.45">-</span>
                    <a-tag v-if="rep.ip_info?.ipv4_latency_ms != null" size="small" style="margin-left: 6px">
                      {{ rep.ip_info.ipv4_latency_ms }}ms
                    </a-tag>
                  </div>
                  <div>
                    <span style="opacity: 0.65">IPv6: </span>
                    <code v-if="rep.ip_info?.ipv6" style="word-break: break-all">{{ rep.ip_info.ipv6 }}</code>
                    <span v-else style="opacity: 0.45">-</span>
                    <a-tag v-if="rep.ip_info?.ipv6_latency_ms != null" size="small" style="margin-left: 6px">
                      {{ rep.ip_info.ipv6_latency_ms }}ms
                    </a-tag>
                  </div>
                  <div>
                    <span style="opacity: 0.65">{{ t('routing.egressLocation') }}: </span>
                    <b>{{ [rep.ip_info?.country_code, rep.ip_info?.city || rep.ip_info?.country].filter(Boolean).join(' · ') || '-' }}</b>
                    <a-tag v-if="rep.ip_info?.cf_colo" size="small" color="cyan" style="margin-left: 6px">
                      CF {{ rep.ip_info.cf_colo }}
                    </a-tag>
                  </div>
                  <div>
                    <span style="opacity: 0.65">ASN / ISP: </span>
                    <span>{{ [rep.ip_info?.asn, rep.ip_info?.org || rep.ip_info?.isp].filter(Boolean).join(' · ') || '-' }}</span>
                  </div>
                </div>
              </a-card>
            </a-col>
          </a-row>

          <!-- Streaming & AI Unlock Matrix -->
          <a-table
            :data-source="egressMatrixRows"
            :columns="egressMatrixColumns"
            :loading="egressProbing"
            row-key="service"
            size="small"
            :pagination="false"
            :scroll="(egressReport.reports || []).length > 2 ? { x: 760 } : { x: 560 }"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'service'">
                <b>{{ record.name }}</b>
              </template>

              <template v-else-if="column.key === 'action'">
                <a-button
                  v-if="record.rec"
                  size="small"
                  type="primary"
                  ghost
                  @click="openRuleFromUnlock(record.service, record.rec.best_group, record.rec.suggested_rule_source, record.rec.suggested_domains)"
                >
                  ➕ → {{ record.rec.best_group }}
                </a-button>
                <a-button
                  v-else-if="groups.length > 0"
                  size="small"
                  @click="openRuleFromService(record.service)"
                >
                  ➕ {{ t('routing.egressAddRuleShort') }}
                </a-button>
                <span v-else style="opacity: 0.45">-</span>
              </template>

              <template v-else-if="record.byTarget[column.key]">
                <div>
                  <a-tag :color="unlockStatusColor(record.byTarget[column.key].status)">
                    {{ unlockStatusLabel(record.byTarget[column.key].status) }}
                    <template v-if="record.byTarget[column.key].region">
                      [{{ record.byTarget[column.key].region }}]
                    </template>
                  </a-tag>
                </div>
                <div style="font-size: 11px; opacity: 0.72; margin-top: 2px">
                  {{ record.byTarget[column.key].detail }}
                  <span v-if="record.byTarget[column.key].latency_ms != null">
                    · {{ record.byTarget[column.key].latency_ms }}ms
                  </span>
                </div>
              </template>

              <template v-else>
                <span style="opacity: 0.45">-</span>
              </template>
            </template>
          </a-table>

          <div style="margin-top: 8px; font-size: 11px; opacity: 0.65; text-align: right">
            {{ t('routing.egressCheckedAt') }}: {{ formatTimestamp(egressReport.checked_at) }}
          </div>
        </template>
      </a-tab-pane>

      <!-- Tab 6: Full YAML Preview -->
      <a-tab-pane key="yaml" :tab="t('routing.yamlTab')">
        <div style="display: flex; justify-content: space-between; margin-bottom: 10px">
          <code>{{ previewPath }}</code>
          <a-space>
            <a-button size="small" @click="copyYaml">Copy YAML</a-button>
            <a-button size="small" type="primary" @click="triggerReload">⚡ {{ t('dashboard.reload') }}</a-button>
          </a-space>
        </div>
        <pre
          style="max-height: 65vh; overflow: auto; padding: 14px; border-radius: 8px; background: rgba(127,127,127,0.12); font-size: 12px"
        >{{ previewYaml }}</pre>
      </a-tab-pane>
    </a-tabs>

    <!-- Outbound Group Modal -->
    <a-modal v-model:open="groupModalOpen" :title="groupForm.id ? `${t('app.edit')} · ${groupForm.name}` : t('routing.addGroup')" width="820px" @ok="saveGroup">
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :span="9">
            <a-form-item :label="t('routing.groupName')" required>
              <a-input v-model:value="groupForm.name" placeholder="warp / proxy-out" />
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item :label="t('routing.groupType')">
              <a-select v-model:value="groupForm.group_type">
                <a-select-option value="selector">selector (手动选择)</a-select-option>
                <a-select-option value="url-test">url-test (自动测速)</a-select-option>
                <a-select-option value="round-robin">round-robin (轮询)</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="7">
            <a-form-item :label="t('app.enable')">
              <a-switch v-model:checked="groupForm.enable" />
            </a-form-item>
          </a-col>
        </a-row>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px">
          <b>{{ t('routing.members') }}</b>
          <a-space size="small">
            <a-button size="small" type="primary" ghost @click="openUriImportModal">
              📋 {{ t('routing.importUriBtn') }}
            </a-button>
            <a-button size="small" type="dashed" @click="addMemberRow">+ {{ t('routing.addMember') }}</a-button>
          </a-space>
        </div>

        <div
          v-for="(m, idx) in groupForm.members"
          :key="idx"
          style="padding: 10px; margin-bottom: 10px; border-radius: 8px; border: 1px solid rgba(127,127,127,0.22)"
        >
          <a-row :gutter="8">
            <a-col :span="5">
              <a-input v-model:value="m.name" placeholder="Node Name" size="small" />
            </a-col>
            <a-col :span="5">
              <a-select v-model:value="m.protocol" size="small" style="width: 100%" @change="onMemberProtoChange(m)">
                <a-select-option value="wireguard">WireGuard (WARP)</a-select-option>
                <a-select-option value="vless">VLESS</a-select-option>
                <a-select-option value="vmess">VMess</a-select-option>
                <a-select-option value="trojan">Trojan</a-select-option>
                <a-select-option value="shadowsocks">Shadowsocks</a-select-option>
                <a-select-option value="hysteria2">Hysteria2 (QUIC)</a-select-option>
                <a-select-option value="tuic">TUIC v5 (QUIC)</a-select-option>
                <a-select-option value="anytls">AnyTLS</a-select-option>
                <a-select-option value="snell">Snell</a-select-option>
                <a-select-option value="socks">SOCKS5</a-select-option>
                <a-select-option value="http">HTTP</a-select-option>
                <a-select-option value="direct">Direct</a-select-option>
                <a-select-option value="group">Group Ref</a-select-option>
              </a-select>
            </a-col>
            <a-col :span="7">
              <a-select
                v-if="m.protocol === 'group'"
                v-model:value="m.address"
                size="small"
                style="width: 100%"
                placeholder="Target Group"
              >
                <a-select-option v-for="g in groups.filter((x) => x.name !== groupForm.name)" :key="g.name" :value="g.name">
                  {{ g.name }}
                </a-select-option>
              </a-select>
              <a-input
                v-else-if="m.protocol !== 'direct'"
                v-model:value="m.address"
                :placeholder="m.protocol === 'wireguard' ? 'engage.cloudflareclient.com:2408' : 'host:port'"
                size="small"
              />
            </a-col>
            <a-col :span="5">
              <a-input
                v-if="['vless', 'vmess', 'tuic'].includes(m.protocol)"
                v-model:value="m.uuid"
                placeholder="UUID"
                size="small"
              />
              <a-input
                v-else-if="!['direct', 'wireguard', 'group'].includes(m.protocol)"
                v-model:value="m.password"
                placeholder="Password"
                size="small"
              />
              <a-input
                v-else-if="m.protocol !== 'group'"
                v-model:value="m.bind_interface"
                :placeholder="t('routing.wgBindInterface')"
                size="small"
              />
            </a-col>
            <a-col :span="2" style="text-align: right">
              <a-button size="small" danger type="text" @click="groupForm.members.splice(idx, 1)">✕</a-button>
            </a-col>
          </a-row>

          <!-- Hysteria2 / TUIC QUIC outbound options -->
          <div v-if="['hysteria2', 'tuic'].includes(m.protocol)" style="margin-top: 8px">
            <a-row :gutter="8" style="align-items: center; margin-bottom: 6px">
              <a-col v-if="m.protocol === 'tuic'" :span="6">
                <a-input v-model:value="m.password" placeholder="TUIC Password" size="small" />
              </a-col>
              <a-col :span="m.protocol === 'tuic' ? 6 : 8">
                <a-input v-model:value="m.sni" placeholder="SNI (e.g. hy2.example.com)" size="small" />
              </a-col>
              <a-col v-if="m.protocol === 'hysteria2'" :span="6">
                <a-input v-model:value="m.hy2_hopping_ports" placeholder="Hopping (e.g. 20000-20100)" size="small" />
              </a-col>
              <a-col v-if="m.protocol === 'hysteria2'" :span="6">
                <a-input v-model:value="m.hy2_obfs_password" placeholder="Salamander Obfs (opt)" size="small" />
              </a-col>
              <a-col v-if="m.protocol === 'tuic'" :span="6">
                <a-select v-model:value="m.tuic_udp_mode" size="small" style="width: 100%">
                  <a-select-option value="native">UDP: native</a-select-option>
                  <a-select-option value="quic">UDP: quic</a-select-option>
                </a-select>
              </a-col>
              <a-col :span="4">
                <a-checkbox v-model:checked="m.verify" style="font-size: 12px">Verify</a-checkbox>
              </a-col>
            </a-row>
          </div>

          <!-- TCP proxy security / transport / REALITY / ShadowTLS / Sudoku / H2Mux options -->
          <div
            v-if="['shadowsocks', 'vless', 'vmess', 'trojan', 'anytls', 'snell', 'socks', 'http'].includes(m.protocol)"
            style="margin-top: 8px"
          >
            <a-row :gutter="8" style="align-items: center">
              <a-col v-if="['shadowsocks', 'vmess', 'snell'].includes(m.protocol)" :span="5">
                <a-input v-model:value="m.cipher" placeholder="Cipher" size="small" />
              </a-col>
              <a-col v-if="['socks', 'http'].includes(m.protocol)" :span="5">
                <a-input v-model:value="m.username" placeholder="Username (opt)" size="small" />
              </a-col>
              <a-col :span="5">
                <a-select v-model:value="m.security" size="small" style="width: 100%" @change="onHopSecurityChange(m)">
                  <a-select-option value="none">Sec: None</a-select-option>
                  <a-select-option value="tls">Sec: TLS</a-select-option>
                  <a-select-option value="reality">Sec: REALITY</a-select-option>
                  <a-select-option value="shadowtls">Sec: ShadowTLS v3</a-select-option>
                </a-select>
              </a-col>
              <a-col v-if="['vless', 'vmess', 'trojan', 'shadowsocks'].includes(m.protocol)" :span="4">
                <a-select v-model:value="m.network" size="small" style="width: 100%">
                  <a-select-option value="tcp">TCP</a-select-option>
                  <a-select-option value="ws">WS</a-select-option>
                  <a-select-option value="xhttp">XHTTP</a-select-option>
                </a-select>
              </a-col>
              <a-col v-if="['vless', 'vmess', 'trojan'].includes(m.protocol)" :span="4">
                <a-checkbox v-model:checked="ensureMemberH2Mux(m).enabled">H2Mux</a-checkbox>
              </a-col>
              <a-col :span="4">
                <a-checkbox v-model:checked="ensureHopSudoku(m).enabled">Sudoku</a-checkbox>
              </a-col>
            </a-row>

            <!-- Security fields -->
            <a-row v-if="m.security === 'tls'" :gutter="8" style="margin-top: 6px; align-items: center">
              <a-col :span="8">
                <a-input v-model:value="m.sni" placeholder="SNI (e.g. proxy.example.com)" size="small" />
              </a-col>
              <a-col :span="6">
                <a-checkbox v-model:checked="m.verify" style="font-size: 12px">Verify Cert</a-checkbox>
                <a-checkbox v-if="m.protocol === 'vless'" v-model:checked="m.vision" style="font-size: 12px">Vision</a-checkbox>
              </a-col>
              <a-col :span="10">
                <a-select
                  v-model:value="m.key_exchange_groups"
                  mode="multiple"
                  size="small"
                  style="width: 100%"
                  placeholder="PQ Key Exchange (opt)"
                >
                  <a-select-option value="X25519MLKEM768">X25519MLKEM768</a-select-option>
                  <a-select-option value="SecP256r1MLKEM768">SecP256r1MLKEM768</a-select-option>
                  <a-select-option value="X25519">X25519</a-select-option>
                </a-select>
              </a-col>
            </a-row>

            <a-row v-if="m.security === 'tls'" :gutter="8" style="margin-top: 6px">
              <a-col :span="12">
                <a-input v-model:value="m.tls_cert" placeholder="mTLS Client Cert Path (opt)" size="small" />
              </a-col>
              <a-col :span="12">
                <a-input v-model:value="m.tls_key" placeholder="mTLS Client Key Path (opt)" size="small" />
              </a-col>
            </a-row>

            <a-row v-if="m.security === 'reality'" :gutter="8" style="margin-top: 6px; align-items: center">
              <a-col :span="6">
                <a-input v-model:value="m.sni" placeholder="SNI" size="small" />
              </a-col>
              <a-col :span="8">
                <a-input v-model:value="m.reality_public_key" placeholder="Public Key (pbk)" size="small" />
              </a-col>
              <a-col :span="5">
                <a-input v-model:value="m.reality_short_id" placeholder="Short ID (sid)" size="small" />
              </a-col>
              <a-col :span="5">
                <a-checkbox v-if="m.protocol === 'vless'" v-model:checked="m.vision" style="font-size: 12px">Vision</a-checkbox>
              </a-col>
            </a-row>
            <a-row v-if="m.security === 'reality'" :gutter="8" style="margin-top: 6px">
              <a-col :span="24">
                <a-input v-model:value="m.reality_mldsa65_verify" placeholder="ML-DSA-65 Verify Key (pqv, optional)" size="small" />
              </a-col>
            </a-row>

            <a-row v-if="m.security === 'shadowtls'" :gutter="8" style="margin-top: 6px">
              <a-col :span="10">
                <a-input v-model:value="m.sni" placeholder="SNI (e.g. www.microsoft.com)" size="small" />
              </a-col>
              <a-col :span="14">
                <a-input v-model:value="m.shadowtls_password" :placeholder="t('inbounds.shadowtlsPassword')" size="small" />
              </a-col>
            </a-row>

            <!-- VLESS native encryption -->
            <a-row v-if="m.protocol === 'vless'" :gutter="8" style="margin-top: 6px">
              <a-col :span="24">
                <a-input v-model:value="m.vless_encryption" placeholder="VLESS Native Encryption (optional, e.g. mlkem768x25519plus...)" size="small" />
              </a-col>
            </a-row>

            <!-- Transport fields (WS / XHTTP) -->
            <a-row v-if="m.network === 'ws'" :gutter="8" style="margin-top: 6px">
              <a-col :span="12">
                <a-input v-model:value="m.ws_path" placeholder="WS Path (e.g. /ws)" size="small" />
              </a-col>
              <a-col :span="12">
                <a-input v-model:value="m.ws_host" placeholder="WS Host Header (optional)" size="small" />
              </a-col>
            </a-row>
            <a-row v-if="m.network === 'xhttp'" :gutter="8" style="margin-top: 6px">
              <a-col :span="9">
                <a-input v-model:value="m.xhttp_path" placeholder="XHTTP Path (e.g. /xhttp)" size="small" />
              </a-col>
              <a-col :span="9">
                <a-input v-model:value="m.xhttp_host" placeholder="XHTTP Host (optional)" size="small" />
              </a-col>
              <a-col :span="6">
                <a-select v-model:value="m.xhttp_mode" size="small" style="width: 100%">
                  <a-select-option value="auto">auto</a-select-option>
                  <a-select-option value="packet-up">packet-up</a-select-option>
                  <a-select-option value="stream-up">stream-up</a-select-option>
                  <a-select-option value="stream-one">stream-one</a-select-option>
                </a-select>
              </a-col>
            </a-row>

            <!-- Sudoku Mask outbound fields -->
            <a-row v-if="ensureHopSudoku(m).enabled" :gutter="8" style="margin-top: 6px">
              <a-col :span="10">
                <a-input v-model:value="m.sudoku.password" placeholder="Sudoku Password" size="small" />
              </a-col>
              <a-col :span="7">
                <a-select v-model:value="m.sudoku.ascii" size="small" style="width: 100%">
                  <a-select-option value="">prefer_entropy</a-select-option>
                  <a-select-option value="entropy">entropy</a-select-option>
                  <a-select-option value="prefer_ascii">prefer_ascii</a-select-option>
                  <a-select-option value="ascii">ascii</a-select-option>
                </a-select>
              </a-col>
              <a-col :span="7">
                <a-input v-model:value="m.sudoku.custom_table" placeholder="Custom Table (opt)" size="small" />
              </a-col>
            </a-row>

            <!-- H2Mux fields -->
            <a-row v-if="['vless', 'vmess', 'trojan'].includes(m.protocol) && ensureMemberH2Mux(m).enabled" :gutter="8" style="margin-top: 6px; align-items: center">
              <a-col :span="6">
                <a-input-number v-model:value="m.h2mux.max_connections" :min="1" :max="64" size="small" style="width: 100%" placeholder="Conns" />
              </a-col>
              <a-col :span="6">
                <a-checkbox v-model:checked="m.h2mux.padding" style="font-size: 12px">H2Mux Padding</a-checkbox>
              </a-col>
            </a-row>
          </div>

          <!-- WireGuard / WARP outbound configuration -->
          <div
            v-if="m.protocol === 'wireguard'"
            style="margin-top: 10px; padding-top: 10px; border-top: 1px dashed rgba(127,127,127,0.25)"
          >
            <a-space wrap size="small" style="margin-bottom: 8px">
              <a-button size="small" type="primary" ghost :loading="warpBusy" @click="fillMemberWithWarp(m)">
                ⚡ {{ t('routing.wgRegisterWarp') }}
              </a-button>
              <a-button size="small" @click="openWgImportModal(m)">
                📋 {{ t('routing.wgImportConf') }}
              </a-button>
              <a-button size="small" @click="genMemberWgKeys(m)">
                🔑 {{ t('routing.wgGenKeys') }}
              </a-button>
            </a-space>

            <a-row :gutter="8" style="margin-bottom: 6px">
              <a-col :span="12">
                <a-input-password v-model:value="m.wg_private_key" size="small" :placeholder="t('routing.wgPrivateKey')" />
              </a-col>
              <a-col :span="12">
                <a-input v-model:value="m.wg_public_key" size="small" :placeholder="t('routing.wgPublicKey')" />
              </a-col>
            </a-row>
            <a-row :gutter="8" style="margin-bottom: 6px">
              <a-col :span="12">
                <a-input v-model:value="m._wg_addresses_text" size="small" :placeholder="t('routing.wgAddresses')" />
              </a-col>
              <a-col :span="12">
                <a-input v-model:value="m._wg_allowed_text" size="small" :placeholder="t('routing.wgAllowedIps')" />
              </a-col>
            </a-row>
            <a-row :gutter="8" style="align-items: center">
              <a-col :span="8">
                <a-input v-model:value="m.wg_preshared_key" size="small" :placeholder="t('routing.wgPsk')" />
              </a-col>
              <a-col :span="4">
                <a-input-number v-model:value="m.wg_mtu" :min="1280" :max="1420" size="small" style="width: 100%" placeholder="MTU 1280" />
              </a-col>
              <a-col :span="4">
                <a-input-number v-model:value="m.wg_keepalive" :min="0" :max="65535" size="small" style="width: 100%" placeholder="KA 25s" />
              </a-col>
              <a-col :span="8">
                <a-checkbox v-model:checked="m._wg_high_throughput" style="font-size: 12px">
                  {{ t('routing.wgHighThroughput') }}
                </a-checkbox>
              </a-col>
            </a-row>
            <div style="font-size: 11px; opacity: 0.7; margin-top: 6px">
              {{ t('routing.wgPlatformNote') }}
            </div>
          </div>

          <!-- Visual Multi-Hop Chain Builder (Hop 2..N) -->
          <div style="margin-top: 8px; padding-top: 8px; border-top: 1px dashed rgba(127,127,127,0.2)">
            <div
              v-for="(hop, hidx) in m.extra_hops || []"
              :key="hidx"
              style="padding: 8px; margin-bottom: 6px; border-radius: 6px; background: rgba(127,127,127,0.08)"
            >
              <a-row :gutter="6" style="align-items: center">
                <a-col :span="3">
                  <a-tag color="geekblue" style="margin: 0">→ {{ t('routing.hopLabel', { n: hidx + 2 }) }}</a-tag>
                </a-col>
                <a-col :span="5">
                  <a-select v-model:value="hop.protocol" size="small" style="width: 100%">
                    <a-select-option value="group">Group Ref</a-select-option>
                    <a-select-option value="socks">SOCKS5</a-select-option>
                    <a-select-option value="http">HTTP</a-select-option>
                    <a-select-option value="vless">VLESS</a-select-option>
                    <a-select-option value="vmess">VMess</a-select-option>
                    <a-select-option value="trojan">Trojan</a-select-option>
                    <a-select-option value="shadowsocks">Shadowsocks</a-select-option>
                    <a-select-option value="anytls">AnyTLS</a-select-option>
                    <a-select-option value="direct">Direct</a-select-option>
                  </a-select>
                </a-col>
                <a-col :span="7">
                  <a-select
                    v-if="hop.protocol === 'group'"
                    v-model:value="hop.address"
                    size="small"
                    style="width: 100%"
                    placeholder="Select group"
                  >
                    <a-select-option v-for="g in groups.filter((x) => x.name !== groupForm.name)" :key="g.name" :value="g.name">
                      {{ g.name }}
                    </a-select-option>
                  </a-select>
                  <a-input
                    v-else-if="hop.protocol !== 'direct'"
                    v-model:value="hop.address"
                    placeholder="host:port"
                    size="small"
                  />
                </a-col>
                <a-col :span="5">
                  <a-input
                    v-if="['vless', 'vmess'].includes(hop.protocol)"
                    v-model:value="hop.uuid"
                    placeholder="UUID"
                    size="small"
                  />
                  <a-input
                    v-else-if="!['group', 'direct'].includes(hop.protocol)"
                    v-model:value="hop.password"
                    placeholder="Password"
                    size="small"
                  />
                </a-col>
                <a-col :span="3">
                  <a-select
                    v-if="!['group', 'direct'].includes(hop.protocol)"
                    v-model:value="hop.security"
                    size="small"
                    style="width: 100%"
                  >
                    <a-select-option value="none">None</a-select-option>
                    <a-select-option value="tls">TLS</a-select-option>
                    <a-select-option value="reality">REALITY</a-select-option>
                    <a-select-option value="shadowtls">ShadowTLS</a-select-option>
                  </a-select>
                </a-col>
                <a-col :span="1" style="text-align: right">
                  <a-button size="small" danger type="text" @click="m.extra_hops.splice(hidx, 1)">✕</a-button>
                </a-col>
              </a-row>
              <a-row
                v-if="!['group', 'direct'].includes(hop.protocol) && ['tls', 'reality', 'shadowtls'].includes(hop.security)"
                :gutter="6"
                style="margin-top: 6px"
              >
                <a-col :span="8">
                  <a-input v-model:value="hop.sni" placeholder="SNI" size="small" />
                </a-col>
                <a-col v-if="hop.security === 'reality'" :span="10">
                  <a-input v-model:value="hop.reality_public_key" placeholder="Public Key (pbk)" size="small" />
                </a-col>
                <a-col v-if="hop.security === 'reality'" :span="6">
                  <a-input v-model:value="hop.reality_short_id" placeholder="Short ID" size="small" />
                </a-col>
                <a-col v-if="hop.security === 'shadowtls'" :span="16">
                  <a-input v-model:value="hop.shadowtls_password" placeholder="ShadowTLS Password" size="small" />
                </a-col>
                <a-col v-if="hop.security === 'tls'" :span="8">
                  <a-checkbox v-model:checked="hop.verify" style="font-size: 12px">Verify Cert</a-checkbox>
                </a-col>
              </a-row>
            </div>
            <a-button size="small" type="link" style="padding: 0" @click="addExtraHop(m)">
              + {{ t('routing.addNextHop') }}
            </a-button>
          </div>
        </div>

        <a-form-item :label="t('routing.rawChainsYaml')" style="margin-top: 10px">
          <a-textarea v-model:value="groupForm.raw_chains_yaml" :rows="3" style="font-family: monospace; font-size: 12px" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- Share URI -> Outbound Member Import Modal -->
    <a-modal
      v-model:open="uriImportOpen"
      :title="t('routing.importUriTitle')"
      width="640px"
      :confirm-loading="uriImporting"
      @ok="applyUriImport"
    >
      <a-textarea
        v-model:value="uriImportText"
        :rows="8"
        style="font-family: monospace; font-size: 12px"
        :placeholder="t('routing.importUriPlaceholder')"
      />
    </a-modal>

    <!-- WireGuard .conf Import Modal -->
    <a-modal v-model:open="wgImportOpen" :title="t('routing.wgImportTitle')" width="600px" @ok="applyWgConfImport">
      <a-textarea
        v-model:value="wgImportText"
        :rows="10"
        style="font-family: monospace; font-size: 12px"
        :placeholder="t('routing.wgImportPlaceholder')"
      />
    </a-modal>

    <!-- Rule Source Group Modal -->
    <a-modal
      v-model:open="ruleSourceModalOpen"
      :title="t('routing.addRuleSource')"
      width="780px"
      :confirm-loading="savingRuleSource"
      @ok="saveRuleSource"
    >
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :span="10">
            <a-form-item :label="t('routing.ruleSourceName')" required>
              <a-input v-model:value="ruleSourceForm.name" placeholder="geosite-openai / geoip-cn" />
            </a-form-item>
          </a-col>
          <a-col :span="10">
            <a-form-item :label="t('app.remark')">
              <a-input v-model:value="ruleSourceForm.remark" placeholder="OpenAI / ChatGPT domains" />
            </a-form-item>
          </a-col>
          <a-col :span="4">
            <a-form-item :label="t('app.enable')">
              <a-switch v-model:checked="ruleSourceForm.enable" />
            </a-form-item>
          </a-col>
        </a-row>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px">
          <b>{{ t('routing.ruleSourceItems') }}</b>
          <a-button size="small" type="dashed" @click="addRuleSourceItem">+ {{ t('routing.addRuleSourceItem') }}</a-button>
        </div>

        <div
          v-for="(item, idx) in ruleSourceForm.items"
          :key="idx"
          style="padding: 10px; margin-bottom: 8px; border-radius: 8px; border: 1px solid rgba(127,127,127,0.22)"
        >
          <a-row :gutter="8" style="margin-bottom: 6px">
            <a-col :span="5">
              <a-select v-model:value="item.source_type" size="small" style="width: 100%">
                <a-select-option value="url">Remote URL</a-select-option>
                <a-select-option value="local">Local File</a-select-option>
              </a-select>
            </a-col>
            <a-col :span="17">
              <a-input
                v-if="item.source_type === 'url'"
                v-model:value="item.url"
                size="small"
                placeholder="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs"
              />
              <a-input
                v-else
                v-model:value="item.path"
                size="small"
                placeholder="/etc/shoes-panel/rules/geoip.dat"
              />
            </a-col>
            <a-col :span="2" style="text-align: right">
              <a-button size="small" danger type="text" @click="ruleSourceForm.items.splice(idx, 1)">✕</a-button>
            </a-col>
          </a-row>

          <a-row :gutter="8" style="margin-bottom: 6px">
            <a-col :span="6">
              <a-select v-model:value="item.format" size="small" style="width: 100%" placeholder="Format">
                <a-select-option value="">Auto Detect</a-select-option>
                <a-select-option value="srs">sing-box (.srs)</a-select-option>
                <a-select-option value="mrs">Mihomo (.mrs)</a-select-option>
                <a-select-option value="singbox_json">sing-box JSON</a-select-option>
                <a-select-option value="mihomo_yaml">Mihomo YAML</a-select-option>
                <a-select-option value="mihomo_text">Mihomo Text</a-select-option>
                <a-select-option value="geosite_dat">V2Ray geosite.dat</a-select-option>
                <a-select-option value="geoip_dat">V2Ray geoip.dat</a-select-option>
              </a-select>
            </a-col>
            <a-col v-if="['mihomo_yaml', 'mihomo_text'].includes(item.format)" :span="6">
              <a-select v-model:value="item.behavior" size="small" style="width: 100%" placeholder="Behavior">
                <a-select-option value="domain">domain</a-select-option>
                <a-select-option value="ipcidr">ipcidr</a-select-option>
                <a-select-option value="classical">classical</a-select-option>
              </a-select>
            </a-col>
            <a-col v-if="['geosite_dat', 'geoip_dat'].includes(item.format)" :span="6">
              <a-input v-model:value="item.code" size="small" :placeholder="t('routing.ruleCode')" />
            </a-col>
            <a-col v-if="item.source_type === 'url'" :span="6">
              <a-input v-model:value="item.update_interval" size="small" placeholder="24h / 7d" />
            </a-col>
            <a-col v-if="item.source_type === 'url'" :span="12">
              <a-select v-model:value="item.sync_mode" size="small" style="width: 100%">
                <a-select-option value="panel">{{ t('routing.syncModePanel') }}</a-select-option>
                <a-select-option value="shoes_native">{{ t('routing.syncModeNative') }}</a-select-option>
              </a-select>
            </a-col>
          </a-row>

          <a-row v-if="item.source_type === 'url' && item.sync_mode === 'shoes_native'" :gutter="8">
            <a-col :span="12">
              <a-select v-model:value="item.download_chain" size="small" style="width: 100%">
                <a-select-option value="direct">direct</a-select-option>
                <a-select-option v-for="g in groups" :key="g.name" :value="g.name">{{ g.name }}</a-select-option>
              </a-select>
            </a-col>
            <a-col :span="12">
              <a-input v-model:value="item.bootstrap_url" size="small" placeholder="system or udp://1.1.1.1" />
            </a-col>
          </a-row>
        </div>
      </a-form>
    </a-modal>

    <!-- Routing Rule Modal -->
    <a-modal v-model:open="ruleModalOpen" :title="t('routing.addRule')" width="600px" @ok="saveRule">
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :span="14">
            <a-form-item :label="t('app.remark')">
              <a-input v-model:value="ruleForm.remark" placeholder="Route OpenAI via WARP / Block CN" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('routing.priority')">
              <a-input-number v-model:value="ruleForm.priority" style="width: 100%" />
            </a-form-item>
          </a-col>
          <a-col :span="4">
            <a-form-item :label="t('app.enable')">
              <a-switch v-model:checked="ruleForm.enable" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="12">
          <a-col :span="12">
            <a-form-item :label="t('routing.matchType')">
              <a-select v-model:value="ruleForm.match_type">
                <a-select-option value="rule_source_group">Rule Set (rule_source_group)</a-select-option>
                <a-select-option value="domain_suffix">Domain Suffix (domain_suffix)</a-select-option>
                <a-select-option value="domain">Exact Domain (domain)</a-select-option>
                <a-select-option value="domain_keyword">Domain Keyword (domain_keyword)</a-select-option>
                <a-select-option value="ip_cidr">IP CIDR (ip_cidr)</a-select-option>
                <a-select-option value="masks">IP CIDR / Host Masks (Legacy)</a-select-option>
                <a-select-option value="destination_port">Destination Port</a-select-option>
                <a-select-option value="network">Network (tcp / udp)</a-select-option>
                <a-select-option value="udp_stun">UDP STUN / DTLS</a-select-option>
                <a-select-option value="any">Catch-All (Any Destination)</a-select-option>
                <a-select-option value="raw_yaml">Raw RuleConfig YAML</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="t('routing.action')">
              <a-select v-model:value="ruleForm.action">
                <a-select-option value="allow">Allow</a-select-option>
                <a-select-option value="block">Block</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col v-if="ruleForm.action === 'allow'" :span="6">
            <a-form-item :label="t('routing.outbound')">
              <a-select v-model:value="ruleForm.outbound">
                <a-select-option value="direct">direct</a-select-option>
                <a-select-option v-for="g in groups" :key="g.name" :value="g.name">{{ g.name }}</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>

        <a-form-item v-if="ruleForm.match_type === 'rule_source_group'" :label="t('routing.selectRuleSource')" required>
          <a-select v-model:value="ruleForm.match_value" placeholder="Select rule_source_group">
            <a-select-option v-for="rs in ruleSources.filter((r) => r.enable)" :key="rs.name" :value="rs.name">
              {{ rs.name }}{{ rs.remark ? ` (${rs.remark})` : '' }}
            </a-select-option>
          </a-select>
        </a-form-item>

        <a-form-item
          v-else-if="!['any', 'udp_stun'].includes(ruleForm.match_type)"
          :label="t('routing.matchValue')"
        >
          <a-textarea
            v-model:value="ruleForm.match_value"
            :rows="4"
            placeholder="e.g. openai.com, netflix.com or 10.0.0.0/8, 192.168.0.0/16"
          />
        </a-form-item>

        <a-row v-if="ruleForm.match_type !== 'raw_yaml'" :gutter="12" style="align-items: center">
          <a-col :span="12">
            <a-checkbox v-model:checked="ruleForm.no_resolve">{{ t('routing.noResolve') }}</a-checkbox>
          </a-col>
          <a-col v-if="ruleForm.action === 'allow'" :span="12">
            <a-form-item :label="t('routing.overrideAddress')" style="margin-bottom: 0">
              <a-input v-model:value="ruleForm.override_address" size="small" placeholder="optional host:port" />
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>
    </a-modal>

    <!-- DNS Group Modal -->
    <a-modal v-model:open="dnsModalOpen" :title="t('routing.addDnsGroup')" width="780px" @ok="saveDnsGroup">
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :span="10">
            <a-form-item :label="t('routing.dnsGroupName')" required>
              <a-input v-model:value="dnsForm.name" placeholder="cf-ipv4 / unlock-dns" />
            </a-form-item>
          </a-col>
          <a-col :span="10">
            <a-form-item :label="t('app.remark')">
              <a-input v-model:value="dnsForm.remark" placeholder="Cloudflare DoH IPv4 only" />
            </a-form-item>
          </a-col>
          <a-col :span="4">
            <a-form-item :label="t('app.enable')">
              <a-switch v-model:checked="dnsForm.enable" />
            </a-form-item>
          </a-col>
        </a-row>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px">
          <b>{{ t('routing.dnsServers') }}</b>
          <a-button size="small" type="dashed" @click="addDnsServerRow">+ {{ t('routing.addDnsServer') }}</a-button>
        </div>

        <div
          v-for="(s, idx) in dnsForm.servers"
          :key="idx"
          style="padding: 10px; margin-bottom: 8px; border-radius: 8px; border: 1px solid rgba(127,127,127,0.22)"
        >
          <a-row :gutter="8" style="margin-bottom: 6px">
            <a-col :span="13">
              <a-input v-model:value="s.url" size="small" :placeholder="t('routing.dnsUrl')" />
            </a-col>
            <a-col :span="9">
              <a-select v-model:value="s.ip_strategy" size="small" style="width: 100%">
                <a-select-option value="">Default (ipv4_then_ipv6)</a-select-option>
                <a-select-option value="ipv4_only">IPv4 Only (ipv4_only)</a-select-option>
                <a-select-option value="ipv4_then_ipv6">IPv4 First (ipv4_then_ipv6)</a-select-option>
                <a-select-option value="ipv6_then_ipv4">IPv6 First (ipv6_then_ipv4)</a-select-option>
                <a-select-option value="ipv6_only">IPv6 Only (ipv6_only)</a-select-option>
                <a-select-option value="ipv4_and_ipv6">Dual Stack (ipv4_and_ipv6)</a-select-option>
              </a-select>
            </a-col>
            <a-col :span="2" style="text-align: right">
              <a-button size="small" danger type="text" @click="dnsForm.servers.splice(idx, 1)">✕</a-button>
            </a-col>
          </a-row>
          <a-row v-if="s.url !== 'system'" :gutter="8">
            <a-col :span="8">
              <a-input v-model:value="s.server_name" size="small" :placeholder="t('routing.dnsServerName')" />
            </a-col>
            <a-col :span="8">
              <a-input v-model:value="s.bootstrap_url" size="small" :placeholder="t('routing.dnsBootstrap')" />
            </a-col>
            <a-col :span="8">
              <a-select v-model:value="s.client_chain" size="small" allow-clear style="width: 100%" :placeholder="t('routing.dnsClientChain')">
                <a-select-option value="">direct</a-select-option>
                <a-select-option v-for="g in groups" :key="g.name" :value="g.name">{{ g.name }}</a-select-option>
              </a-select>
            </a-col>
          </a-row>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin: 12px 0 6px">
          <b>{{ t('routing.dnsHosts') }}</b>
          <a-button size="small" type="dashed" @click="dnsForm.hostsRows.push({ host: '', ips: '' })">
            + {{ t('routing.addHostRow') }}
          </a-button>
        </div>
        <div v-for="(hr, idx) in dnsForm.hostsRows" :key="idx" style="margin-bottom: 6px">
          <a-row :gutter="8">
            <a-col :span="10">
              <a-input v-model:value="hr.host" size="small" placeholder="e.g. www.netflix.com" />
            </a-col>
            <a-col :span="12">
              <a-input v-model:value="hr.ips" size="small" placeholder="e.g. 203.0.113.10, 203.0.113.11" />
            </a-col>
            <a-col :span="2" style="text-align: right">
              <a-button size="small" danger type="text" @click="dnsForm.hostsRows.splice(idx, 1)">✕</a-button>
            </a-col>
          </a-row>
        </div>
      </a-form>
    </a-modal>
  </a-card>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { useI18n } from 'vue-i18n';
import { api } from '../api';
import { copyText, formatBytes } from '../utils';

const { t } = useI18n();
const activeTab = ref('outbounds');
const groups = ref([]);
const ruleSources = ref([]);
const rules = ref([]);
const dnsGroups = ref([]);
const liveGroups = ref([]);
const delays = reactive({});
const probing = ref('');
const warpBusy = ref(false);
const savingRuleSource = ref(false);
const syncingRuleSourceId = ref(0);
const savingDefaultDns = ref(false);
const fullSettingsCache = ref(null);

const previewYaml = ref('');
const previewPath = ref('');

const RULE_SOURCE_PRESETS = [
  {
    name: 'geosite-openai',
    label: 'OpenAI / ChatGPT (.srs)',
    remark: 'OpenAI & ChatGPT domains',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs',
    format: 'srs',
  },
  {
    name: 'geosite-netflix',
    label: 'Netflix (.srs)',
    remark: 'Netflix streaming domains',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs',
    format: 'srs',
  },
  {
    name: 'geosite-anthropic',
    label: 'Claude / Anthropic (.srs)',
    remark: 'Anthropic & Claude domains',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/anthropic.srs',
    format: 'srs',
  },
  {
    name: 'geosite-disney',
    label: 'Disney+ (.srs)',
    remark: 'Disney+ streaming domains',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/disney.srs',
    format: 'srs',
  },
  {
    name: 'geosite-youtube',
    label: 'YouTube (.srs)',
    remark: 'YouTube domains',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs',
    format: 'srs',
  },
  {
    name: 'geosite-cn',
    label: 'GeoSite CN (.srs)',
    remark: 'China mainland domains',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs',
    format: 'srs',
  },
  {
    name: 'geoip-cn',
    label: 'GeoIP CN (.srs)',
    remark: 'China mainland IP CIDRs',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs',
    format: 'srs',
  },
  {
    name: 'geosite-ads',
    label: 'Ads Block (.srs)',
    remark: 'Ad-blocking domains',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ads-all.srs',
    format: 'srs',
  },
  {
    name: 'geoip-private',
    label: 'Private LAN IP (.srs)',
    remark: 'RFC1918 & local IPs',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.srs',
    format: 'srs',
  },
];

const DNS_PRESETS = [
  {
    name: 'cf-ipv4',
    label: 'Cloudflare DoH (IPv4 Only)',
    remark: 'Cloudflare DoH forcing IPv4',
    servers: [{ url: 'https://1.1.1.1/dns-query', ip_strategy: 'ipv4_only', server_name: 'cloudflare-dns.com', bootstrap_url: '', client_chain: '' }],
  },
  {
    name: 'cf-doh',
    label: 'Cloudflare DoH (IPv4 First)',
    remark: 'Cloudflare DoH IPv4 preferred',
    servers: [{ url: 'https://1.1.1.1/dns-query', ip_strategy: 'ipv4_then_ipv6', server_name: 'cloudflare-dns.com', bootstrap_url: '', client_chain: '' }],
  },
  {
    name: 'google-doh',
    label: 'Google DoH (IPv4 First)',
    remark: 'Google DoH IPv4 preferred',
    servers: [{ url: 'https://8.8.8.8/dns-query', ip_strategy: 'ipv4_then_ipv6', server_name: 'dns.google', bootstrap_url: '', client_chain: '' }],
  },
  {
    name: 'system-ipv4',
    label: 'System DNS (IPv4 Only)',
    remark: 'OS resolver IPv4 only',
    servers: [{ url: 'system', ip_strategy: 'ipv4_only', server_name: '', bootstrap_url: '', client_chain: '' }],
  },
];

const groupModalOpen = ref(false);
const groupForm = reactive({
  id: 0,
  name: '',
  enable: true,
  group_type: 'selector',
  default_member: '',
  test_url: 'https://www.gstatic.com/generate_204',
  interval_secs: 300,
  timeout_ms: 5000,
  tolerance_ms: 50,
  members: [],
  raw_chains_yaml: '',
  remark: '',
});

const wgImportOpen = ref(false);
const wgImportText = ref('');
const wgImportTarget = ref(null);
const uriImportOpen = ref(false);
const uriImportText = ref('');
const uriImporting = ref(false);

const ruleSourceModalOpen = ref(false);
const ruleSourceForm = reactive({
  id: 0,
  name: '',
  enable: true,
  remark: '',
  items: [],
});

const ruleModalOpen = ref(false);
const ruleForm = reactive({
  id: 0,
  priority: 100,
  enable: true,
  remark: '',
  match_type: 'rule_source_group',
  match_value: '',
  action: 'allow',
  outbound: 'direct',
  no_resolve: false,
  override_address: '',
});

const defaultDnsForm = reactive({
  default_dns_group: '',
  default_dns_ip_strategy: '',
  hostsRows: [],
});

const dnsModalOpen = ref(false);
const dnsForm = reactive({
  id: 0,
  name: '',
  enable: true,
  remark: '',
  servers: [],
  hostsRows: [],
});

const groupColumns = computed(() => [
  { title: t('app.status'), key: 'enable', width: 80 },
  { title: t('routing.groupName'), dataIndex: 'name', key: 'name', width: 150 },
  { title: t('routing.groupType'), key: 'group_type', width: 120 },
  { title: t('routing.members'), key: 'members' },
  { title: t('app.actions'), key: 'actions', width: 245 },
]);

const ruleSourceColumns = computed(() => [
  { title: t('app.status'), key: 'enable', width: 75 },
  { title: t('routing.ruleSourceName'), dataIndex: 'name', key: 'name', width: 160 },
  { title: t('routing.ruleSourceItems'), key: 'sources' },
  { title: t('routing.ruleCacheStatus'), key: 'status', width: 220 },
  { title: t('app.actions'), key: 'actions', width: 220 },
]);

const ruleColumns = computed(() => [
  { title: '#', dataIndex: 'priority', key: 'priority', width: 65 },
  { title: t('app.status'), key: 'enable', width: 75 },
  { title: t('app.remark'), dataIndex: 'remark', key: 'remark', width: 170 },
  { title: t('routing.matchType'), key: 'match_type', width: 175 },
  { title: t('routing.matchValue'), dataIndex: 'match_value', key: 'match_value', ellipsis: true },
  { title: t('routing.action'), key: 'action', width: 90 },
  { title: t('routing.outbound'), key: 'outbound', width: 130 },
  { title: t('app.actions'), key: 'actions', width: 150 },
]);

const dnsGroupColumns = computed(() => [
  { title: t('app.status'), key: 'enable', width: 75 },
  { title: t('routing.dnsGroupName'), key: 'name', width: 200 },
  { title: t('routing.dnsServers'), key: 'servers' },
  { title: t('routing.dnsHosts'), key: 'hosts', width: 110 },
  { title: t('app.actions'), key: 'actions', width: 230 },
]);

function formatTimestamp(ms) {
  if (!ms) return '-';
  return new Date(ms).toLocaleString();
}

function hostsMapToRows(hostsMap) {
  return Object.entries(hostsMap || {}).map(([host, ips]) => ({
    host,
    ips: Array.isArray(ips) ? ips.join(', ') : String(ips || ''),
  }));
}

function hostsRowsToMap(rows) {
  const out = {};
  for (const row of rows || []) {
    const h = (row.host || '').trim();
    if (!h) continue;
    const ips = String(row.ips || '')
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (ips.length > 0) {
      out[h] = ips;
    }
  }
  return out;
}

async function loadAll() {
  const [gs, rss, rs, dgs, cp, st] = await Promise.all([
    api.listOutboundGroups().catch(() => []),
    api.listRuleSources().catch(() => []),
    api.listRoutingRules().catch(() => []),
    api.listDnsGroups().catch(() => []),
    api.clashProxies().catch(() => ({ proxies: {} })),
    api.getSettings().catch(() => null),
  ]);
  groups.value = gs;
  ruleSources.value = rss;
  rules.value = rs;
  dnsGroups.value = dgs;
  if (!egressOptsInitialized.value && gs.length > 0) {
    const warp = gs.find((g) => g.enable && g.name.toLowerCase().includes('warp'));
    const firstEnabled = gs.find((g) => g.enable);
    if (warp) egressOpts.selectedGroups = [warp.name];
    else if (firstEnabled) egressOpts.selectedGroups = [firstEnabled.name];
    egressOptsInitialized.value = true;
  }
  const map = cp?.proxies || {};
  liveGroups.value = Object.values(map).filter((p) => ['Selector', 'URLTest', 'LoadBalance'].includes(p.type));
  if (st?.settings) {
    fullSettingsCache.value = st.settings;
    const cg = st.settings.core_global || {};
    defaultDnsForm.default_dns_group = cg.default_dns_group || '';
    defaultDnsForm.default_dns_ip_strategy = cg.default_dns_ip_strategy || '';
    defaultDnsForm.hostsRows = hostsMapToRows(cg.default_dns_hosts);
  }
}

onMounted(loadAll);

async function onTabChange(k) {
  if (k === 'yaml') {
    const res = await api.shoesConfigPreview().catch(() => ({ yaml: '', path: '' }));
    previewYaml.value = res.yaml;
    previewPath.value = res.path;
  }
}

// ==================== Outbound Groups & WireGuard / WARP ====================

function defaultH2Mux() {
  return { enabled: false, max_connections: 4, min_streams: 4, max_streams: 0, padding: false };
}

function defaultSudoku() {
  return { enabled: false, password: '', ascii: '', custom_table: '', custom_tables: [], padding_min: 0, padding_max: 0 };
}

function ensureMemberH2Mux(m) {
  if (!m.h2mux) m.h2mux = defaultH2Mux();
  return m.h2mux;
}

function ensureHopSudoku(m) {
  if (!m.sudoku) m.sudoku = defaultSudoku();
  return m.sudoku;
}

function memberEffectiveSec(m) {
  if (m.security) return m.security;
  if (m.shadowtls) return 'shadowtls';
  if (m.reality_public_key) return 'reality';
  if (m.tls) return 'tls';
  return 'none';
}

function memberTagColor(m) {
  if (m.protocol === 'wireguard') return 'orange';
  if (m.extra_hops?.length > 0) return 'purple';
  const sec = memberEffectiveSec(m);
  if (sec === 'shadowtls') return 'magenta';
  if (sec === 'reality') return 'gold';
  if (['hysteria2', 'tuic'].includes(m.protocol)) return 'volcano';
  return undefined;
}

function formatMemberSummary(m) {
  const parts = [m.protocol];
  const sec = memberEffectiveSec(m);
  if (sec === 'reality') parts.push('REALITY');
  else if (sec === 'shadowtls') parts.push('ShadowTLS');
  if (m.sudoku?.enabled) parts.push('Sudoku');
  if (m.h2mux?.enabled) parts.push('H2Mux');
  if (m.extra_hops?.length > 0) {
    parts.push(`${1 + m.extra_hops.length} hops`);
  }
  return `${m.name} (${parts.join(' · ')})`;
}

function hydrateHopForUi(h = {}) {
  const sec = h.security || (h.shadowtls ? 'shadowtls' : h.reality_public_key ? 'reality' : h.tls ? 'tls' : 'none');
  return {
    protocol: h.protocol || 'socks',
    address: h.address || '',
    uuid: h.uuid || '',
    username: h.username || '',
    password: h.password || '',
    cipher: h.cipher || (h.protocol === 'snell' ? 'aes-128-gcm' : 'aes-256-gcm'),
    security: sec,
    tls: sec === 'tls',
    shadowtls: sec === 'shadowtls',
    shadowtls_password: h.shadowtls_password || '',
    sni: h.sni || '',
    verify: h.verify !== false,
    alpn: Array.isArray(h.alpn) ? [...h.alpn] : [],
    tls_cert: h.tls_cert || '',
    tls_key: h.tls_key || '',
    server_fingerprints: Array.isArray(h.server_fingerprints) ? [...h.server_fingerprints] : [],
    key_exchange_groups: Array.isArray(h.key_exchange_groups) ? [...h.key_exchange_groups] : [],
    reality_public_key: h.reality_public_key || '',
    reality_short_id: h.reality_short_id || '',
    reality_mldsa65_verify: h.reality_mldsa65_verify || '',
    vision: Boolean(h.vision),
    vless_encryption: h.vless_encryption || '',
    network: h.network || 'tcp',
    ws_path: h.ws_path || '',
    ws_host: h.ws_host || '',
    xhttp_path: h.xhttp_path || '',
    xhttp_host: h.xhttp_host || '',
    xhttp_mode: h.xhttp_mode || 'auto',
    hy2_obfs_password: h.hy2_obfs_password || '',
    hy2_hopping_ports: h.hy2_hopping_ports || '',
    tuic_udp_mode: h.tuic_udp_mode || 'native',
    h2mux: h.h2mux ? { ...defaultH2Mux(), ...h.h2mux } : defaultH2Mux(),
    sudoku: h.sudoku ? { ...defaultSudoku(), ...h.sudoku } : defaultSudoku(),
    bind_interface: h.bind_interface || '',
    wg_private_key: h.wg_private_key || '',
    wg_public_key: h.wg_public_key || '',
    wg_preshared_key: h.wg_preshared_key || '',
    wg_addresses: Array.isArray(h.wg_addresses) ? [...h.wg_addresses] : [],
    wg_allowed_ips: Array.isArray(h.wg_allowed_ips) ? [...h.wg_allowed_ips] : ['0.0.0.0/0', '::/0'],
    wg_mtu: h.wg_mtu || 1280,
    wg_keepalive: h.wg_keepalive ?? 25,
    wg_tcp_buffer_size: h.wg_tcp_buffer_size || null,
    wg_tcp_memory_bytes: h.wg_tcp_memory_bytes || null,
    _wg_addresses_text: (h.wg_addresses || []).join(', '),
    _wg_allowed_text: (h.wg_allowed_ips?.length ? h.wg_allowed_ips : ['0.0.0.0/0', '::/0']).join(', '),
    _wg_high_throughput: Boolean(h.wg_tcp_buffer_size && h.wg_tcp_buffer_size >= 262144),
  };
}

function hydrateMemberForUi(m) {
  return {
    name: m.name || 'node-1',
    ...hydrateHopForUi(m),
    extra_hops: Array.isArray(m.extra_hops) ? m.extra_hops.map(hydrateHopForUi) : [],
  };
}

function serializeHopFromUi(h) {
  const splitList = (txt) =>
    String(txt || '')
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  const sec = h.security || 'none';
  const out = {
    protocol: h.protocol,
    address: (h.address || '').trim(),
    uuid: (h.uuid || '').trim(),
    username: (h.username || '').trim(),
    password: (h.password || '').trim(),
    cipher: (h.cipher || '').trim(),
    security: sec,
    tls: sec === 'tls',
    shadowtls: sec === 'shadowtls',
    shadowtls_password: (h.shadowtls_password || '').trim(),
    sni: (h.sni || '').trim(),
    verify: h.verify !== false,
    alpn: Array.isArray(h.alpn) ? h.alpn : [],
    tls_cert: (h.tls_cert || '').trim(),
    tls_key: (h.tls_key || '').trim(),
    server_fingerprints: Array.isArray(h.server_fingerprints) ? h.server_fingerprints : [],
    key_exchange_groups: Array.isArray(h.key_exchange_groups) ? h.key_exchange_groups : [],
    reality_public_key: (h.reality_public_key || '').trim(),
    reality_short_id: (h.reality_short_id || '').trim(),
    reality_mldsa65_verify: (h.reality_mldsa65_verify || '').trim(),
    vision: Boolean(h.vision),
    vless_encryption: (h.vless_encryption || '').trim(),
    network: h.network || 'tcp',
    ws_path: (h.ws_path || '').trim(),
    ws_host: (h.ws_host || '').trim(),
    xhttp_path: (h.xhttp_path || '').trim(),
    xhttp_host: (h.xhttp_host || '').trim(),
    xhttp_mode: (h.xhttp_mode || '').trim(),
    hy2_obfs_password: (h.hy2_obfs_password || '').trim(),
    hy2_hopping_ports: (h.hy2_hopping_ports || '').trim(),
    tuic_udp_mode: (h.tuic_udp_mode || 'native').trim(),
    h2mux: h.h2mux ? { ...h.h2mux } : defaultH2Mux(),
    sudoku: h.sudoku ? { ...h.sudoku } : defaultSudoku(),
    bind_interface: (h.bind_interface || '').trim(),
    wg_private_key: (h.wg_private_key || '').trim(),
    wg_public_key: (h.wg_public_key || '').trim(),
    wg_preshared_key: (h.wg_preshared_key || '').trim(),
    wg_addresses: splitList(h._wg_addresses_text),
    wg_allowed_ips: splitList(h._wg_allowed_text),
    wg_mtu: Number(h.wg_mtu) || 0,
    wg_keepalive: Number(h.wg_keepalive) || 0,
    wg_tcp_buffer_size: h._wg_high_throughput ? 262144 : null,
    wg_tcp_memory_bytes: h._wg_high_throughput ? 268435456 : null,
  };
  if (['wireguard', 'direct', 'group', 'hysteria2', 'tuic'].includes(out.protocol)) {
    out.h2mux.enabled = false;
    out.sudoku.enabled = false;
  }
  if (['wireguard', 'direct', 'group'].includes(out.protocol)) {
    out.security = 'none';
    out.tls = false;
    out.shadowtls = false;
  }
  return out;
}

function serializeMemberFromUi(m) {
  return {
    name: (m.name || '').trim(),
    ...serializeHopFromUi(m),
    extra_hops: (m.extra_hops || []).map(serializeHopFromUi),
  };
}

function onHopSecurityChange(m) {
  m.tls = m.security === 'tls';
  m.shadowtls = m.security === 'shadowtls';
}

function addExtraHop(m) {
  if (!Array.isArray(m.extra_hops)) m.extra_hops = [];
  const otherGroup = groups.value.find((g) => g.name !== groupForm.name)?.name || '';
  m.extra_hops.push(
    hydrateHopForUi(
      otherGroup
        ? { protocol: 'group', address: otherGroup }
        : { protocol: 'socks', address: '127.0.0.1:1080' }
    )
  );
}

function openUriImportModal() {
  uriImportText.value = '';
  uriImportOpen.value = true;
}

async function applyUriImport() {
  uriImporting.value = true;
  try {
    const res = await api.parseOutboundUri(uriImportText.value);
    const parsed = (res?.members || []).map(hydrateMemberForUi);
    if (parsed.length === 0) {
      message.warning('No valid share URIs parsed');
      return;
    }
    // Replace default placeholder row if user hasn't touched it
    if (
      groupForm.members.length === 1 &&
      groupForm.members[0].protocol === 'socks' &&
      groupForm.members[0].address === '127.0.0.1:1080'
    ) {
      groupForm.members.splice(0, 1);
    }
    groupForm.members.push(...parsed);
    uriImportOpen.value = false;
    message.success(`Imported ${parsed.length} outbound node(s)`);
  } catch (e) {
    message.error(e.message);
  } finally {
    uriImporting.value = false;
  }
}

function onMemberProtoChange(m) {
  if (!['vless', 'vmess', 'trojan'].includes(m.protocol) && m.h2mux) {
    m.h2mux.enabled = false;
  }
  if (['wireguard', 'direct', 'group'].includes(m.protocol)) {
    m.security = 'none';
    m.tls = false;
    m.shadowtls = false;
  } else if (['trojan', 'anytls', 'hysteria2', 'tuic'].includes(m.protocol) && m.security === 'none') {
    m.security = 'tls';
    m.tls = true;
  }
  if (m.protocol === 'wireguard') {
    if (!m.address || m.address === '127.0.0.1:1080') {
      m.address = 'engage.cloudflareclient.com:2408';
    }
    if (!m.wg_mtu) m.wg_mtu = 1280;
    if (!m._wg_allowed_text) m._wg_allowed_text = '0.0.0.0/0, ::/0';
  }
}

function addMemberRow() {
  groupForm.members.push(
    hydrateMemberForUi({
      name: `node-${groupForm.members.length + 1}`,
      protocol: 'socks',
      address: '127.0.0.1:1080',
    })
  );
}

function openNewGroup() {
  Object.assign(groupForm, {
    id: 0,
    name: 'upstream-pool',
    enable: true,
    group_type: 'selector',
    default_member: '',
    test_url: 'https://www.gstatic.com/generate_204',
    interval_secs: 300,
    timeout_ms: 5000,
    tolerance_ms: 50,
    members: [],
    raw_chains_yaml: '',
    remark: '',
  });
  addMemberRow();
  groupModalOpen.value = true;
}

async function openQuickWarpGroup() {
  warpBusy.value = true;
  const hide = message.loading(t('routing.warpCreating'), 0);
  try {
    const profile = await api.registerWarp();
    const existing = groups.value.find((g) => g.name === 'warp');
    Object.assign(groupForm, {
      id: existing ? existing.id : 0,
      name: existing ? existing.name : 'warp',
      enable: true,
      group_type: 'selector',
      default_member: 'warp-cf',
      test_url: 'https://www.gstatic.com/generate_204',
      interval_secs: 300,
      timeout_ms: 5000,
      tolerance_ms: 50,
      members: [
        hydrateMemberForUi({
          name: 'warp-cf',
          protocol: 'wireguard',
          ...profile,
          wg_tcp_buffer_size: 262144,
          wg_tcp_memory_bytes: 268435456,
        }),
      ],
      raw_chains_yaml: '',
      remark: 'Cloudflare WARP WireGuard Outbound',
    });
    message.success(t('routing.warpReady'));
    groupModalOpen.value = true;
  } catch (e) {
    message.error(e.message);
  } finally {
    hide();
    warpBusy.value = false;
  }
}

async function fillMemberWithWarp(m) {
  warpBusy.value = true;
  try {
    const profile = await api.registerWarp();
    m.address = profile.address;
    m.wg_private_key = profile.wg_private_key;
    m.wg_public_key = profile.wg_public_key;
    m.wg_preshared_key = profile.wg_preshared_key || '';
    m._wg_addresses_text = (profile.wg_addresses || []).join(', ');
    m._wg_allowed_text = (profile.wg_allowed_ips || ['0.0.0.0/0', '::/0']).join(', ');
    m.wg_mtu = profile.wg_mtu || 1280;
    m.wg_keepalive = profile.wg_keepalive ?? 25;
    m._wg_high_throughput = true;
    message.success(t('routing.warpReady'));
  } catch (e) {
    message.error(e.message);
  } finally {
    warpBusy.value = false;
  }
}

function openWgImportModal(m) {
  wgImportTarget.value = m;
  wgImportText.value = '';
  wgImportOpen.value = true;
}

async function applyWgConfImport() {
  if (!wgImportTarget.value) return;
  try {
    const parsed = await api.parseWgConf(wgImportText.value);
    const m = wgImportTarget.value;
    m.address = parsed.address;
    m.wg_private_key = parsed.wg_private_key;
    m.wg_public_key = parsed.wg_public_key;
    m.wg_preshared_key = parsed.wg_preshared_key || '';
    m._wg_addresses_text = (parsed.wg_addresses || []).join(', ');
    m._wg_allowed_text = (parsed.wg_allowed_ips || ['0.0.0.0/0', '::/0']).join(', ');
    m.wg_mtu = parsed.wg_mtu || 1280;
    m.wg_keepalive = parsed.wg_keepalive ?? 25;
    wgImportOpen.value = false;
    message.success('Imported WireGuard config');
  } catch (e) {
    message.error(e.message);
  }
}

async function genMemberWgKeys(m) {
  try {
    const res = await api.genWireguard();
    m.wg_private_key = res.private_key;
    message.success(`Generated PrivateKey (PublicKey: ${res.public_key.slice(0, 12)}...)`);
  } catch (e) {
    message.error(e.message);
  }
}

function openEditGroup(rec) {
  const copy = JSON.parse(JSON.stringify(rec));
  copy.members = (copy.members || []).map(hydrateMemberForUi);
  Object.assign(groupForm, copy);
  groupModalOpen.value = true;
}

async function saveGroup() {
  try {
    const payload = {
      ...JSON.parse(JSON.stringify(groupForm)),
      members: groupForm.members.map(serializeMemberFromUi),
    };
    await api.saveOutboundGroup(payload);
    message.success(t('app.saveSuccess'));
    groupModalOpen.value = false;
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function delGroup(rec) {
  try {
    await api.deleteOutboundGroup(rec.id);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function selectMember(groupName, member) {
  try {
    await api.clashSelectProxy(groupName, member);
    message.success(`${groupName} → ${member}`);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function probeGroup(groupName) {
  probing.value = groupName;
  try {
    const res = await api.clashDelay('group', groupName);
    Object.assign(delays, res || {});
  } catch (e) {
    message.error(e.message);
  } finally {
    probing.value = '';
  }
}

// ==================== Rule Sources (GeoIP / GeoSite / SRS / MRS) ====================

function defaultRuleSourceItem(overrides = {}) {
  return {
    source_type: 'url',
    sync_mode: 'panel',
    url: '',
    path: '',
    format: '',
    behavior: '',
    code: '',
    attributes: [],
    update_interval: '24h',
    download_chain: 'direct',
    bootstrap_url: 'system',
    last_updated_at: 0,
    file_size: 0,
    last_error: '',
    ...overrides,
  };
}

function addRuleSourceItem() {
  ruleSourceForm.items.push(defaultRuleSourceItem());
}

function openNewRuleSource() {
  Object.assign(ruleSourceForm, {
    id: 0,
    name: '',
    enable: true,
    remark: '',
    items: [defaultRuleSourceItem()],
  });
  ruleSourceModalOpen.value = true;
}

function openRuleSourcePreset(preset) {
  const existing = ruleSources.value.find((r) => r.name === preset.name);
  Object.assign(ruleSourceForm, {
    id: existing ? existing.id : 0,
    name: preset.name,
    enable: true,
    remark: preset.remark,
    items: [
      defaultRuleSourceItem({
        url: preset.url,
        format: preset.format || '',
        update_interval: '24h',
      }),
    ],
  });
  ruleSourceModalOpen.value = true;
}

function openEditRuleSource(rec) {
  Object.assign(ruleSourceForm, JSON.parse(JSON.stringify(rec)));
  if (!ruleSourceForm.items?.length) {
    ruleSourceForm.items = [defaultRuleSourceItem()];
  }
  ruleSourceModalOpen.value = true;
}

async function saveRuleSource() {
  savingRuleSource.value = true;
  try {
    await api.saveRuleSource(JSON.parse(JSON.stringify(ruleSourceForm)));
    message.success(t('app.saveSuccess'));
    ruleSourceModalOpen.value = false;
    await loadAll();
  } catch (e) {
    message.error(e.message);
  } finally {
    savingRuleSource.value = false;
  }
}

async function syncRuleSourceNow(rec) {
  syncingRuleSourceId.value = rec.id;
  try {
    await api.syncRuleSource(rec.id);
    message.success(t('routing.syncedOk'));
    await loadAll();
  } catch (e) {
    message.error(e.message);
  } finally {
    syncingRuleSourceId.value = 0;
  }
}

async function delRuleSource(rec) {
  try {
    await api.deleteRuleSource(rec.id);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

// ==================== Routing Rules ====================

function openNewRule() {
  Object.assign(ruleForm, {
    id: 0,
    priority: 100,
    enable: true,
    remark: '',
    match_type: ruleSources.value.length > 0 ? 'rule_source_group' : 'domain_suffix',
    match_value: ruleSources.value[0]?.name || '',
    action: 'allow',
    outbound: groups.value[0]?.name || 'direct',
    no_resolve: false,
    override_address: '',
  });
  ruleModalOpen.value = true;
}

function openQuickRuleTemplate(kind) {
  const hasRs = (name) => ruleSources.value.some((r) => r.enable && r.name === name);
  const warpGroup = groups.value.find((g) => g.enable && g.name.toLowerCase().includes('warp'))?.name || groups.value[0]?.name || 'direct';

  if (kind === 'openai_warp') {
    Object.assign(ruleForm, {
      id: 0,
      priority: 20,
      enable: true,
      remark: 'ChatGPT / OpenAI → WARP',
      match_type: hasRs('geosite-openai') ? 'rule_source_group' : 'domain_suffix',
      match_value: hasRs('geosite-openai') ? 'geosite-openai' : 'openai.com, chatgpt.com, oaistatic.com, oaiusercontent.com',
      action: 'allow',
      outbound: warpGroup,
      no_resolve: false,
      override_address: '',
    });
  } else if (kind === 'netflix_warp') {
    Object.assign(ruleForm, {
      id: 0,
      priority: 30,
      enable: true,
      remark: 'Netflix → WARP',
      match_type: hasRs('geosite-netflix') ? 'rule_source_group' : 'domain_suffix',
      match_value: hasRs('geosite-netflix') ? 'geosite-netflix' : 'netflix.com, nflxvideo.net, nflxso.net, nflximg.net',
      action: 'allow',
      outbound: warpGroup,
      no_resolve: false,
      override_address: '',
    });
  } else if (kind === 'block_private') {
    Object.assign(ruleForm, {
      id: 0,
      priority: 10,
      enable: true,
      remark: 'Block Private LAN',
      match_type: hasRs('geoip-private') ? 'rule_source_group' : 'ip_cidr',
      match_value: hasRs('geoip-private') ? 'geoip-private' : '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, fc00::/7',
      action: 'block',
      outbound: 'direct',
      no_resolve: true,
      override_address: '',
    });
  } else if (kind === 'block_cn') {
    const targetRs = hasRs('geoip-cn') ? 'geoip-cn' : hasRs('geosite-cn') ? 'geosite-cn' : '';
    Object.assign(ruleForm, {
      id: 0,
      priority: 40,
      enable: true,
      remark: 'Block Mainland CN',
      match_type: targetRs ? 'rule_source_group' : 'domain_suffix',
      match_value: targetRs || 'cn',
      action: 'block',
      outbound: 'direct',
      no_resolve: targetRs === 'geoip-cn',
      override_address: '',
    });
  } else if (kind === 'block_ads') {
    Object.assign(ruleForm, {
      id: 0,
      priority: 50,
      enable: true,
      remark: 'Block Ads',
      match_type: hasRs('geosite-ads') ? 'rule_source_group' : 'domain_keyword',
      match_value: hasRs('geosite-ads') ? 'geosite-ads' : 'doubleclick, adservice',
      action: 'block',
      outbound: 'direct',
      no_resolve: false,
      override_address: '',
    });
  }
  ruleModalOpen.value = true;
}

function openEditRule(rec) {
  Object.assign(ruleForm, {
    no_resolve: false,
    override_address: '',
    ...JSON.parse(JSON.stringify(rec)),
  });
  ruleModalOpen.value = true;
}

async function saveRule() {
  try {
    await api.saveRoutingRule({ ...ruleForm });
    message.success(t('app.saveSuccess'));
    ruleModalOpen.value = false;
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function delRule(rec) {
  try {
    await api.deleteRoutingRule(rec.id);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

// ==================== DNS & Hosts ====================

async function saveDefaultDns() {
  savingDefaultDns.value = true;
  try {
    const latest = fullSettingsCache.value || (await api.getSettings()).settings;
    const payload = {
      ...latest,
      core_global: {
        ...(latest.core_global || {}),
        default_dns_group: defaultDnsForm.default_dns_group || '',
        default_dns_ip_strategy: defaultDnsForm.default_dns_group ? '' : defaultDnsForm.default_dns_ip_strategy || '',
        default_dns_hosts: hostsRowsToMap(defaultDnsForm.hostsRows),
      },
    };
    const saved = await api.saveSettings(payload);
    fullSettingsCache.value = saved;
    message.success(t('app.saveSuccess'));
  } catch (e) {
    message.error(e.message);
  } finally {
    savingDefaultDns.value = false;
  }
}

async function setDefaultDnsGroup(name) {
  defaultDnsForm.default_dns_group = name;
  await saveDefaultDns();
}

function addDnsServerRow() {
  dnsForm.servers.push({
    url: 'https://1.1.1.1/dns-query',
    ip_strategy: 'ipv4_only',
    server_name: '',
    bootstrap_url: '',
    client_chain: '',
  });
}

function openNewDnsGroup() {
  Object.assign(dnsForm, {
    id: 0,
    name: '',
    enable: true,
    remark: '',
    servers: [],
    hostsRows: [],
  });
  addDnsServerRow();
  dnsModalOpen.value = true;
}

function openDnsPreset(preset) {
  const existing = dnsGroups.value.find((g) => g.name === preset.name);
  Object.assign(dnsForm, {
    id: existing ? existing.id : 0,
    name: preset.name,
    enable: true,
    remark: preset.remark,
    servers: JSON.parse(JSON.stringify(preset.servers)),
    hostsRows: existing ? hostsMapToRows(existing.hosts) : [],
  });
  dnsModalOpen.value = true;
}

function openEditDnsGroup(rec) {
  const copy = JSON.parse(JSON.stringify(rec));
  Object.assign(dnsForm, {
    id: copy.id,
    name: copy.name,
    enable: copy.enable,
    remark: copy.remark || '',
    servers: (copy.servers || []).map((s) => ({
      url: s.url || '',
      ip_strategy: s.ip_strategy || '',
      server_name: s.server_name || '',
      bootstrap_url: s.bootstrap_url || '',
      client_chain: s.client_chain || '',
    })),
    hostsRows: hostsMapToRows(copy.hosts),
  });
  if (!dnsForm.servers.length) addDnsServerRow();
  dnsModalOpen.value = true;
}

async function saveDnsGroup() {
  try {
    await api.saveDnsGroup({
      id: dnsForm.id,
      name: dnsForm.name,
      enable: dnsForm.enable,
      remark: dnsForm.remark,
      servers: dnsForm.servers.filter((s) => (s.url || '').trim()),
      hosts: hostsRowsToMap(dnsForm.hostsRows),
    });
    message.success(t('app.saveSuccess'));
    dnsModalOpen.value = false;
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function delDnsGroup(rec) {
  try {
    await api.deleteDnsGroup(rec.id);
    await loadAll();
  } catch (e) {
    message.error(e.message);
  }
}

async function copyYaml() {
  await copyText(previewYaml.value);
  message.success(t('app.copied'));
}

async function triggerReload() {
  try {
    const res = await api.shoesReload();
    previewYaml.value = res.yaml;
    message.success(t('app.saveSuccess'));
  } catch (e) {
    message.error(e.message);
  }
}

// ==================== VPS Egress Quality & Streaming / AI Unlock Diagnostics ====================

const egressProbing = ref(false);
const egressReport = ref(null);
const egressOptsInitialized = ref(false);
const egressOpts = reactive({
  includeDirectV4: true,
  includeDirectV6: true,
  selectedGroups: [],
  groupIpVersion: 'auto',
});

const SERVICE_ROUTING_META = {
  chatgpt: {
    name: 'ChatGPT / OpenAI',
    priority: 20,
    ruleSource: 'geosite-openai',
    domains: ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com'],
  },
  claude: {
    name: 'Claude / Anthropic',
    priority: 22,
    ruleSource: 'geosite-anthropic',
    domains: ['anthropic.com', 'claude.ai'],
  },
  gemini: {
    name: 'Google Gemini',
    priority: 24,
    ruleSource: 'geosite-google-gemini',
    domains: ['gemini.google.com', 'generativelanguage.googleapis.com', 'aistudio.google.com'],
  },
  netflix: {
    name: 'Netflix',
    priority: 30,
    ruleSource: 'geosite-netflix',
    domains: ['netflix.com', 'nflxvideo.net', 'nflxso.net', 'nflximg.net'],
  },
  disney: {
    name: 'Disney+',
    priority: 32,
    ruleSource: 'geosite-disney',
    domains: ['disneyplus.com', 'disney-plus.net', 'bamgrid.com', 'dssott.com'],
  },
  youtube: {
    name: 'YouTube Premium',
    priority: 34,
    ruleSource: 'geosite-youtube',
    domains: ['youtube.com', 'googlevideo.com', 'ytimg.com', 'youtu.be'],
  },
};

const hasWarpGroup = computed(() =>
  groups.value.some(
    (g) =>
      g.name.toLowerCase().includes('warp') ||
      (g.members || []).some((m) => m.protocol === 'wireguard')
  )
);

const directHasBlockedServices = computed(() => {
  const reports = egressReport.value?.reports || [];
  return reports
    .filter((r) => r.kind === 'direct' && r.ok)
    .some((r) => (r.services || []).some((s) => s.status === 'blocked' || s.status === 'partial'));
});

const egressMatrixColumns = computed(() => {
  const reps = egressReport.value?.reports || [];
  const wide = reps.length > 2;
  const cols = [
    { title: t('routing.egressServiceCol'), key: 'service', width: 148, ...(wide ? { fixed: 'left' } : {}) },
  ];
  for (const r of reps) {
    cols.push({ title: r.label, key: r.target_id, width: 175 });
  }
  cols.push({ title: t('app.actions'), key: 'action', width: 112, ...(wide ? { fixed: 'right' } : {}) });
  return cols;
});

const egressMatrixRows = computed(() => {
  const reps = egressReport.value?.reports || [];
  const recs = egressReport.value?.recommendations || [];
  const recMap = Object.fromEntries(recs.map((r) => [r.service, r]));
  const order = ['chatgpt', 'claude', 'gemini', 'netflix', 'disney', 'youtube'];
  return order.map((svc) => {
    const byTarget = {};
    let name = SERVICE_ROUTING_META[svc]?.name || svc;
    for (const rep of reps) {
      const found = (rep.services || []).find((s) => s.service === svc);
      if (found) {
        byTarget[rep.target_id] = found;
        if (found.name) name = found.name;
      }
    }
    return {
      service: svc,
      name,
      byTarget,
      rec: recMap[svc] || null,
    };
  });
});

function unlockStatusColor(status) {
  if (status === 'unlocked') return 'success';
  if (status === 'partial') return 'warning';
  if (status === 'blocked') return 'error';
  return 'default';
}

function unlockStatusLabel(status) {
  if (status === 'unlocked') return t('routing.egressUnlocked');
  if (status === 'partial') return t('routing.egressPartial');
  if (status === 'blocked') return t('routing.egressBlocked');
  return t('routing.egressError');
}

async function runEgressProbe(compareAll = false) {
  egressProbing.value = true;
  try {
    let payload;
    if (compareAll) {
      payload = { compare_all: true, timeout_ms: 10000 };
    } else {
      const targets = [];
      if (egressOpts.includeDirectV4) {
        targets.push({ kind: 'direct', ip_version: 'ipv4' });
      }
      if (egressOpts.includeDirectV6) {
        targets.push({ kind: 'direct', ip_version: 'ipv6' });
      }
      for (const gname of egressOpts.selectedGroups) {
        targets.push({
          kind: 'outbound_group',
          group_name: gname,
          ip_version: egressOpts.groupIpVersion || 'auto',
        });
      }
      if (targets.length === 0) {
        message.warning(t('routing.egressSelectTargetWarn'));
        egressProbing.value = false;
        return;
      }
      payload = { targets, timeout_ms: 10000 };
    }
    egressReport.value = await api.probeEgress(payload);
  } catch (e) {
    message.error(e.message);
  } finally {
    egressProbing.value = false;
  }
}

async function probeOutboundUnlock(rec) {
  activeTab.value = 'egress';
  egressOpts.includeDirectV4 = true;
  egressOpts.includeDirectV6 = false;
  egressOpts.selectedGroups = [rec.name];
  egressOptsInitialized.value = true;
  await runEgressProbe(false);
}

function openRuleFromUnlock(service, targetGroup, suggestedRuleSource, suggestedDomains) {
  const meta = SERVICE_ROUTING_META[service] || { name: service, priority: 30, ruleSource: '', domains: [] };
  const rsName = suggestedRuleSource || meta.ruleSource;
  const hasRs = rsName && ruleSources.value.some((r) => r.enable && r.name === rsName);
  const domains = suggestedDomains?.length ? suggestedDomains : meta.domains;
  Object.assign(ruleForm, {
    id: 0,
    priority: meta.priority,
    enable: true,
    remark: `${meta.name} → ${targetGroup}`,
    match_type: hasRs ? 'rule_source_group' : 'domain_suffix',
    match_value: hasRs ? rsName : domains.join(', '),
    action: 'allow',
    outbound: targetGroup,
    no_resolve: false,
    override_address: '',
  });
  ruleModalOpen.value = true;
}

function openRuleFromService(service) {
  const warp = groups.value.find((g) => g.enable && g.name.toLowerCase().includes('warp'));
  const target = warp?.name || groups.value.find((g) => g.enable)?.name || groups.value[0]?.name || 'direct';
  const meta = SERVICE_ROUTING_META[service] || {};
  openRuleFromUnlock(service, target, meta.ruleSource, meta.domains);
}
</script>
