<template>
  <div class="settings-page" v-loading="loading">
    <div class="page-header">
      <div class="title-section">
        <h1 class="page-title">Client settings</h1>
        <p class="page-subtitle">
          Everything above the proxies: which server to reach, how to reach it,
          and how this client is administered. Saving rewrites only these keys —
          proxies and visitors are left exactly as they are. Comments are not
          preserved, so a config you annotate is better edited on the Config
          (raw) page.
        </p>
      </div>
      <div class="header-actions">
        <ActionButton :loading="saving" @click="save">Save</ActionButton>
      </div>
    </div>

    <!-- label-position="top" is what every other form page uses; without the
         wrapper el-form-item falls back to labels beside the input and the
         page stops looking like the rest of the app. -->
    <el-form label-position="top" class="settings-form" @submit.prevent>

    <ConfigSection title="Server">
      <div class="field-row two-col">
        <ConfigField label="Server address" v-model="cfg.serverAddr"
          tip="Host or IP of frps." />
        <ConfigField label="Server port" type="number" v-model="cfg.serverPort" :min="0" :max="65535"
          tip="frps bindPort. 7000 by default." />
      </div>
      <div class="field-row three-col">
        <ConfigField label="User" v-model="cfg.user"
          tip="Prefixed to every proxy name, so two clients can share names." />
        <ConfigField label="Client ID" v-model="cfg.clientID"
          tip="Identifies this instance across reconnects. Generated when empty." />
        <ConfigField label="Exit if login fails" type="switch" v-model="loginFailExit" class="switch-field"
          tip="Off means keep retrying." />
      </div>
    </ConfigSection>

    <ConfigSection title="Transport">
      <div class="field-row three-col">
        <ConfigField label="Protocol" type="select" v-model="cfg.transport.protocol"
          :options="protocolOptions"
          tip="How the control connection reaches frps. wss forces TLS on and looks like ordinary https in transit, so it gets through proxies and inspection that block the rest." />
        <ConfigField label="Wire protocol" type="select" v-model="cfg.transport.wireProtocol"
          :options="wireOptions"
          tip="Message framing. Leave alone unless both ends are this fork." />
        <ConfigField label="Pool count" type="number" v-model="cfg.transport.poolCount" :min="0"
          tip="Work connections kept ready. Higher saves a round trip per visitor." />
      </div>
      <div class="field-row three-col">
        <ConfigField label="Dial timeout (s)" type="number" v-model="cfg.transport.dialServerTimeout" :min="0" />
        <ConfigField label="Dial keepalive (s)" type="number" v-model="cfg.transport.dialServerKeepalive" :min="0" />
        <ConfigField label="TCP mux" type="switch" v-model="tcpMux" class="switch-field"
          tip="On unless frps has it off." />
      </div>
      <div class="field-row two-col">
        <ConfigField label="Heartbeat interval (s)" type="number" v-model="cfg.transport.heartbeatInterval" :min="-1"
          tip="-1 disables it, which only makes sense with tcpMux on." />
        <ConfigField label="Heartbeat timeout (s)" type="number" v-model="cfg.transport.heartbeatTimeout" :min="-1" />
      </div>
      <div class="field-row two-col">
        <ConfigField label="Connect from local IP" v-model="cfg.transport.connectServerLocalIP"
          tip="Source address to dial from, for hosts with more than one." />
        <ConfigField label="Proxy URL" v-model="cfg.transport.proxyURL"
          tip="Reach frps through an http or socks5 proxy, e.g. socks5://127.0.0.1:1080." />
      </div>
    </ConfigSection>

    <ConfigSection title="TLS" collapsible :has-value="tlsEnable === true || !!cfg.transport.tls.certFile">
      <p class="hint">
        Ignored when the protocol is wss, which forces TLS on and cannot be
        turned off from here.
      </p>
      <div class="field-row three-col">
        <ConfigField label="Enable" type="switch" v-model="tlsEnable" class="switch-field" />
        <ConfigField label="Server name" v-model="cfg.transport.tls.serverName"
          tip="Name to verify the certificate against. Defaults to the server address." />
        <ConfigField label="Disable custom first byte" type="switch" v-model="tlsDisableFirstByte" class="switch-field"
          tip="Turn on when frps sits behind something that will not pass frp's TLS marker byte." />
      </div>
      <div class="field-row three-col">
        <ConfigField label="Certificate file" v-model="cfg.transport.tls.certFile" />
        <ConfigField label="Key file" v-model="cfg.transport.tls.keyFile" />
        <ConfigField label="Trusted CA file" v-model="cfg.transport.tls.trustedCaFile" />
      </div>
    </ConfigSection>

    <ConfigSection title="Auth">
      <div class="field-row three-col">
        <ConfigField label="Method" type="select" v-model="cfg.auth.method" :options="authMethods" />
        <ConfigField label="Token" type="password" v-model="cfg.auth.token"
          tip="Must match frps. This is the whole of the client's identity." />
        <ConfigField label="Additional scopes" type="tags" v-model="authScopes"
          tip="HeartBeats, NewWorkConns — what else to sign beyond login." />
      </div>
      <!-- Hidden unless chosen: eight OIDC fields on a page nobody is using
           them on is most of what made this hard to read. -->
      <template v-if="cfg.auth.method === 'oidc'">
        <div class="field-row three-col">
          <ConfigField label="OIDC client ID" v-model="cfg.auth.oidc.clientID" />
          <ConfigField label="OIDC client secret" type="password" v-model="cfg.auth.oidc.clientSecret" />
          <ConfigField label="OIDC audience" v-model="cfg.auth.oidc.audience" />
        </div>
        <div class="field-row two-col">
          <ConfigField label="OIDC scope" v-model="cfg.auth.oidc.scope" />
          <ConfigField label="OIDC token endpoint" v-model="cfg.auth.oidc.tokenEndpointURL" />
        </div>
      </template>
    </ConfigSection>

    <ConfigSection title="Admin interface">
      <p class="hint">
        This page. Address defaults to 127.0.0.1, and the rest only starts to
        matter once that changes — the api here can stop the client, rewrite its
        config and read the auth token back.
      </p>
      <div class="field-row two-col">
        <ConfigField label="Address" v-model="cfg.webServer.addr"
          tip="127.0.0.1 keeps it to this machine. Anything else exposes it." />
        <ConfigField label="Port" type="number" v-model="cfg.webServer.port" :min="0" :max="65535"
          tip="0 disables the admin server entirely." />
      </div>
      <div class="field-row three-col">
        <ConfigField label="User" v-model="cfg.webServer.user" />
        <ConfigField label="Password" type="password" v-model="cfg.webServer.password" />
        <ConfigField label="pprof" type="switch" v-model="cfg.webServer.pprofEnable" class="switch-field"
          tip="Go profiling handlers. Not something to expose." />
      </div>
      <ConfigField label="Allowed CIDRs" type="tags" v-model="allowCIDRs"
        tip="Who may reach this port at all. Empty means everybody. Worth reaching for first once the address is not loopback: a peer not on the list never reaches the login form." />
      <div class="field-row two-col">
        <ConfigField label="Ban after failed logins" type="number" v-model="cfg.webServer.maxLoginFailures" :min="0"
          tip="0 is off. A low number is right here — nobody who belongs gets the password wrong repeatedly." />
        <ConfigField label="Ban seconds" type="number" v-model="cfg.webServer.loginBanSeconds" :min="0"
          tip="600 by default. Never extended by retries, so a mistyped password cannot lock you out for good." />
      </div>
    </ConfigSection>

    <ConfigSection title="Log" collapsible :has-value="!!cfg.log.to || !!cfg.log.level">
      <div class="field-row two-col">
        <ConfigField label="To" v-model="cfg.log.to" tip="File path, or console." />
        <ConfigField label="Level" type="select" v-model="cfg.log.level" :options="logLevels" />
      </div>
      <div class="field-row two-col">
        <ConfigField label="Max days" type="number" v-model="cfg.log.maxDays" :min="0" />
        <ConfigField label="Disable colour" type="switch" v-model="cfg.log.disablePrintColor" class="switch-field" />
      </div>
    </ConfigSection>

    <ConfigSection title="Other" collapsible
      :has-value="!!cfg.dnsServer || !!cfg.natHoleStunServer || !!cfg.udpPacketSize">
      <div class="field-row three-col">
        <ConfigField label="DNS server" v-model="cfg.dnsServer"
          tip="Resolver to use instead of the system one." />
        <ConfigField label="NAT hole STUN server" v-model="cfg.natHoleStunServer"
          tip="Used by xtcp to find its own public address." />
        <ConfigField label="UDP packet size" type="number" v-model="cfg.udpPacketSize" :min="0"
          tip="1500 by default. Both ends must agree." />
      </div>
      <div class="field-row two-col">
        <ConfigField label="Start only these proxies" type="tags" v-model="start"
          tip="Empty starts all of them." />
        <ConfigField label="Include files" type="tags" v-model="includes"
          tip="Extra files holding proxies, e.g. ./confd/*.toml." />
      </div>
      <ConfigField label="Metadata" type="kv" v-model="cfg.metadatas"
        tip="Passed to frps and on to its plugins." />
    </ConfigSection>

    </el-form>

    <el-dialog v-model="confirm.open" title="Save client settings" width="520px">
      <p>
        These settings decide how this client reaches frps. Getting them wrong
        means it cannot connect, and it cannot be fixed from this page once that
        happens — you would need access to the machine itself.
      </p>
      <p v-if="confirm.risky" class="risky">{{ confirm.risky }}</p>
      <template #footer>
        <el-button @click="confirm.open = false">Cancel</el-button>
        <el-button type="primary" :loading="saving" @click="doSave">Save</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { http } from '../api/http'
import ConfigSection from '../components/ConfigSection.vue'
import ConfigField from '../components/ConfigField.vue'
import ActionButton from '@shared/components/ActionButton.vue'

const protocolOptions = [
  { label: 'tcp (default)', value: 'tcp' },
  { label: 'kcp', value: 'kcp' },
  { label: 'quic', value: 'quic' },
  { label: 'websocket', value: 'websocket' },
  { label: 'wss (TLS always on)', value: 'wss' },
]
const wireOptions = [
  { label: 'v1 (default)', value: 'v1' },
  { label: 'v2', value: 'v2' },
]
const authMethods = [
  { label: 'token', value: 'token' },
  { label: 'oidc', value: 'oidc' },
]
const logLevels = ['trace', 'debug', 'info', 'warn', 'error'].map((v) => ({ label: v, value: v }))

// The shape the api speaks. Anything the form does not name is still carried
// through untouched by the server, so this does not have to be exhaustive to be
// safe to save.
function empty(): any {
  return {
    serverAddr: '', serverPort: 0, user: '', clientID: '',
    dnsServer: '', natHoleStunServer: '', udpPacketSize: 0,
    loginFailExit: null, start: [], includes: [], metadatas: {},
    auth: { method: 'token', token: '', additionalScopes: [], oidc: {} },
    transport: { protocol: '', wireProtocol: '', poolCount: 0, tcpMux: null, tls: {} },
    webServer: { addr: '', port: 0, user: '', password: '', allowCIDRs: [] },
    log: {},
  }
}

const loading = ref(false)
const saving = ref(false)
const cfg = reactive<any>(empty())
const confirm = reactive({ open: false, risky: '' })

// Tri-state booleans arrive as null when unset and must go back as null rather
// than false: a config that says nothing lets frp pick its own default, while
// one that says false has made a choice.
function tri(path: string[]) {
  return computed({
    get: () => path.reduce((o: any, k) => o?.[k], cfg) ?? null,
    set: (v: boolean | null) => {
      const parent = path.slice(0, -1).reduce((o: any, k) => (o[k] ??= {}), cfg)
      parent[path[path.length - 1]] = v
    },
  })
}
const loginFailExit = tri(['loginFailExit'])
const tcpMux = tri(['transport', 'tcpMux'])
const tlsEnable = tri(['transport', 'tls', 'enable'])
const tlsDisableFirstByte = tri(['transport', 'tls', 'disableCustomTLSFirstByte'])

function list(path: string[]) {
  return computed({
    get: () => path.reduce((o: any, k) => o?.[k], cfg) ?? [],
    set: (v: string[]) => {
      const parent = path.slice(0, -1).reduce((o: any, k) => (o[k] ??= {}), cfg)
      parent[path[path.length - 1]] = v
    },
  })
}
const start = list(['start'])
const includes = list(['includes'])
const authScopes = list(['auth', 'additionalScopes'])
const allowCIDRs = list(['webServer', 'allowCIDRs'])

async function load() {
  loading.value = true
  try {
    const res = await http.get<{ common: any }>('../api/common')
    const c = res.common || {}
    Object.assign(cfg, empty(), c)
    // Nested objects need filling in too, or a field the file omitted would
    // bind to undefined and never save.
    cfg.auth = {
      method: 'token', token: '', additionalScopes: [],
      ...(c.auth || {}), oidc: { ...(c.auth?.oidc || {}) },
    }
    cfg.transport = { ...(c.transport || {}), tls: { ...(c.transport?.tls || {}) } }
    cfg.webServer = { allowCIDRs: [], ...(c.webServer || {}) }
    cfg.log = { ...(c.log || {}) }
    cfg.metadatas = { ...(c.metadatas || {}) }
  } catch (e: any) {
    ElMessage.error('Load failed: ' + (e.message || e))
  } finally {
    loading.value = false
  }
}

function save() {
  const warnings: string[] = []
  const addr = cfg.webServer.addr
  if (addr && addr !== '127.0.0.1' && addr !== 'localhost' && !cfg.webServer.allowCIDRs?.length) {
    warnings.push(
      'The admin interface is bound to a non-loopback address with no allowed CIDRs, which exposes an api that can stop this client and read its token.',
    )
  }
  if (!cfg.serverAddr) {
    warnings.push('No server address is set, so this client has nothing to connect to.')
  }
  confirm.risky = warnings.join(' ')
  confirm.open = true
}

async function doSave() {
  saving.value = true
  try {
    await http.put('../api/common', { common: cfg })
    confirm.open = false
    ElMessage.success('Saved. Reload the client for it to take effect.')
    await load()
  } catch (e: any) {
    ElMessage.error('Save failed: ' + (e.message || e))
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped lang="scss">
@use '@/assets/css/form-layout';

/* Same shell as Config (raw) and the proxy editor: a centred column rather
   than fields stretched across the whole window.

   The app shell sets overflow:hidden on #content, so nothing scrolls unless a
   page says which part of it does. Without that the sections past the fold are
   simply unreachable - the header stays put and the form scrolls under it. */
.settings-page {
  display: flex;
  flex-direction: column;
  height: 100%;
  max-width: 960px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  flex-shrink: 0;
  padding: $spacing-xl 40px $spacing-lg;
}

.settings-form {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  /* Room under the last section so it does not sit flush against the edge. */
  padding: 0 40px 80px;
}

.title-section {
  min-width: 0;
}

.page-title {
  margin: 0 0 6px;
  font-size: 20px;
}

/* The shared sections carry no outer margin, so a page stacking several of
   them has to space them itself. */
.settings-form :deep(.config-section-card) {
  margin-bottom: 16px;
}

.page-subtitle,
.hint {
  margin: 0 0 12px;
  font-size: 12px;
  color: var(--text-secondary, #909399);
  line-height: 1.6;
}

.risky {
  color: var(--el-color-warning, #e6a23c);
  font-size: 13px;
}

@include mobile {
  .page-header {
    padding: $spacing-lg $spacing-lg $spacing-sm;
  }

  .settings-form {
    padding: 0 $spacing-lg 80px;
  }
}
</style>
