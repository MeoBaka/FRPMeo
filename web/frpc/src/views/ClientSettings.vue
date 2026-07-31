<template>
  <div class="client-settings" v-loading="loading">
    <div class="page-head">
      <div>
        <h1 class="page-title">Client settings</h1>
        <p class="page-subtitle">
          Everything above the proxies: which server to reach, how to reach it,
          and how this client is administered. Saving rewrites only these keys -
          proxies and visitors are left exactly as they are. Comments are not
          preserved, so a config you annotate is better edited on the Config
          page.
        </p>
      </div>
      <el-button type="primary" :loading="saving" @click="save">Save</el-button>
    </div>

    <ConfigSection title="Server">
      <ConfigField label="Server address" v-model="cfg.serverAddr"
        tip="Host or IP of frps." />
      <ConfigField label="Server port" type="number" v-model="cfg.serverPort" :min="0" :max="65535"
        tip="frps bindPort. 7000 by default." />
      <ConfigField label="User" v-model="cfg.user"
        tip="Prefixed to every proxy name, so two clients can use the same names." />
      <ConfigField label="Client ID" v-model="cfg.clientID"
        tip="Identifies this instance across reconnects. Generated when empty." />
      <ConfigField label="Exit if login fails" type="switch" v-model="loginFailExit"
        tip="Off means keep retrying, which is usually what an unattended client wants." />
    </ConfigSection>

    <ConfigSection title="Transport">
      <ConfigField label="Protocol" type="select" v-model="cfg.transport.protocol"
        :options="protocolOptions"
        tip="How the control connection reaches frps. wss forces TLS on and looks like ordinary https to anything in between, which gets through proxies and inspection that block the rest." />
      <ConfigField label="Wire protocol" type="select" v-model="cfg.transport.wireProtocol"
        :options="[{ label: 'v1 (default)', value: 'v1' }, { label: 'v2', value: 'v2' }]"
        tip="Message framing. Leave alone unless both ends are this fork." />
      <ConfigField label="Pool count" type="number" v-model="cfg.transport.poolCount" :min="0"
        tip="Work connections kept ready. Higher removes a round trip per visitor and costs idle connections." />
      <ConfigField label="TCP mux" type="switch" v-model="tcpMux"
        tip="Multiplexes work connections over one socket. On unless frps has it off." />
      <ConfigField label="Dial timeout (s)" type="number" v-model="cfg.transport.dialServerTimeout" :min="0" />
      <ConfigField label="Dial keepalive (s)" type="number" v-model="cfg.transport.dialServerKeepalive" :min="0" />
      <ConfigField label="Heartbeat interval (s)" type="number" v-model="cfg.transport.heartbeatInterval" :min="-1"
        tip="-1 disables it, which only makes sense with tcpMux on." />
      <ConfigField label="Heartbeat timeout (s)" type="number" v-model="cfg.transport.heartbeatTimeout" :min="-1" />
      <ConfigField label="Connect from local IP" v-model="cfg.transport.connectServerLocalIP"
        tip="Source address to dial from, for hosts with more than one." />
      <ConfigField label="Proxy URL" v-model="cfg.transport.proxyURL"
        tip="Reach frps through an http or socks5 proxy, e.g. socks5://127.0.0.1:1080." />
    </ConfigSection>

    <ConfigSection title="TLS" collapsible :has-value="tlsEnable === true || !!cfg.transport.tls.certFile">
      <p class="hint">
        Ignored when the protocol is wss - that forces TLS on and cannot be
        turned off from here.
      </p>
      <ConfigField label="Enable" type="switch" v-model="tlsEnable" />
      <ConfigField label="Server name" v-model="cfg.transport.tls.serverName"
        tip="Name to verify the certificate against. Defaults to the server address." />
      <ConfigField label="Certificate file" v-model="cfg.transport.tls.certFile" />
      <ConfigField label="Key file" v-model="cfg.transport.tls.keyFile" />
      <ConfigField label="Trusted CA file" v-model="cfg.transport.tls.trustedCaFile" />
      <ConfigField label="Disable custom first byte" type="switch" v-model="tlsDisableFirstByte"
        tip="Turn on when frps is behind something that will not pass frp's TLS marker byte." />
    </ConfigSection>

    <ConfigSection title="Auth">
      <ConfigField label="Method" type="select" v-model="cfg.auth.method"
        :options="[{ label: 'token', value: 'token' }, { label: 'oidc', value: 'oidc' }]" />
      <ConfigField label="Token" type="password" v-model="cfg.auth.token"
        tip="Must match frps. This is the whole of the client's identity, so treat the config file accordingly." />
      <ConfigField label="Additional scopes" type="tags" v-model="authScopes"
        tip="HeartBeats, NewWorkConns - what else to sign beyond login." />
      <ConfigField label="OIDC client ID" v-model="cfg.auth.oidc.clientID" />
      <ConfigField label="OIDC client secret" type="password" v-model="cfg.auth.oidc.clientSecret" />
      <ConfigField label="OIDC audience" v-model="cfg.auth.oidc.audience" />
      <ConfigField label="OIDC scope" v-model="cfg.auth.oidc.scope" />
      <ConfigField label="OIDC token endpoint" v-model="cfg.auth.oidc.tokenEndpointURL" />
    </ConfigSection>

    <ConfigSection title="Admin interface">
      <p class="hint">
        This page. Addr defaults to 127.0.0.1, and everything below only starts
        to matter once that changes - the api here can stop the client, rewrite
        its config and read the auth token back.
      </p>
      <ConfigField label="Address" v-model="cfg.webServer.addr"
        tip="127.0.0.1 keeps it to this machine. Anything else exposes it." />
      <ConfigField label="Port" type="number" v-model="cfg.webServer.port" :min="0" :max="65535"
        tip="0 disables the admin server entirely." />
      <ConfigField label="User" v-model="cfg.webServer.user" />
      <ConfigField label="Password" type="password" v-model="cfg.webServer.password" />
      <ConfigField label="Allowed CIDRs" type="tags" v-model="allowCIDRs"
        tip="Who may reach this port at all. Empty means everybody. The setting worth reaching for first once the address is not loopback: a peer not on the list never reaches the login form." />
      <ConfigField label="Ban after failed logins" type="number" v-model="cfg.webServer.maxLoginFailures" :min="0"
        tip="0 is off. A low number is right here - nobody who belongs gets the password wrong repeatedly." />
      <ConfigField label="Ban seconds" type="number" v-model="cfg.webServer.loginBanSeconds" :min="0"
        tip="600 by default. Never extended by further attempts, so a mistyped password does not lock you out for good." />
      <ConfigField label="pprof" type="switch" v-model="cfg.webServer.pprofEnable"
        tip="Go profiling handlers. Off unless you are debugging - they are not something to expose." />
    </ConfigSection>

    <ConfigSection title="Log" collapsible :has-value="!!cfg.log.to || !!cfg.log.level">
      <ConfigField label="To" v-model="cfg.log.to"
        tip="File path, or console." />
      <ConfigField label="Level" type="select" v-model="cfg.log.level"
        :options="['trace', 'debug', 'info', 'warn', 'error'].map((v) => ({ label: v, value: v }))" />
      <ConfigField label="Max days" type="number" v-model="cfg.log.maxDays" :min="0" />
      <ConfigField label="Disable colour" type="switch" v-model="cfg.log.disablePrintColor" />
    </ConfigSection>

    <ConfigSection title="Other" collapsible
      :has-value="!!cfg.dnsServer || !!cfg.natHoleStunServer || !!cfg.udpPacketSize">
      <ConfigField label="DNS server" v-model="cfg.dnsServer"
        tip="Resolver to use instead of the system one." />
      <ConfigField label="NAT hole STUN server" v-model="cfg.natHoleStunServer"
        tip="Used by xtcp to find its own public address." />
      <ConfigField label="UDP packet size" type="number" v-model="cfg.udpPacketSize" :min="0"
        tip="1500 by default. Both ends must agree." />
      <ConfigField label="Start only these proxies" type="tags" v-model="start"
        tip="Empty starts all of them." />
      <ConfigField label="Include files" type="tags" v-model="includes"
        tip="Extra files holding proxies, e.g. ./confd/*.toml." />
      <ConfigField label="Metadata" type="kv" v-model="cfg.metadatas"
        tip="Passed to frps and on to its plugins." />
    </ConfigSection>

    <el-dialog v-model="confirm.open" title="Save client settings" width="520px">
      <p>
        These settings decide how this client reaches frps. Getting them wrong
        means it cannot connect, and it cannot be fixed from this page once that
        happens - you would need access to the machine itself.
      </p>
      <p v-if="confirm.risky" class="risky">
        {{ confirm.risky }}
      </p>
      <template #footer>
        <el-button @click="confirm.open = false">Cancel</el-button>
        <el-button type="primary" :loading="saving" @click="doSave">Save and reload</el-button>
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

const protocolOptions = [
  { label: 'tcp (default)', value: 'tcp' },
  { label: 'kcp', value: 'kcp' },
  { label: 'quic', value: 'quic' },
  { label: 'websocket', value: 'websocket' },
  { label: 'wss (TLS always on)', value: 'wss' },
]

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

// Tri-state booleans arrive as null when unset, and must go back as null rather
// than false: a config that says nothing lets frp pick its own default, while
// one that says false has made a choice.
function tri(path: string[]) {
  return computed({
    get: () => path.reduce((o, k) => o?.[k], cfg) ?? null,
    set: (v: boolean | null) => {
      const parent = path.slice(0, -1).reduce((o, k) => (o[k] ??= {}), cfg)
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
    get: () => path.reduce((o, k) => o?.[k], cfg) ?? [],
    set: (v: string[]) => {
      const parent = path.slice(0, -1).reduce((o, k) => (o[k] ??= {}), cfg)
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
    cfg.auth = { method: 'token', token: '', additionalScopes: [], ...(c.auth || {}), oidc: { ...(c.auth?.oidc || {}) } }
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
  if (cfg.webServer.addr && cfg.webServer.addr !== '127.0.0.1' && cfg.webServer.addr !== 'localhost') {
    if (!cfg.webServer.allowCIDRs?.length) {
      warnings.push('The admin interface is bound to a non-loopback address with no allowed CIDRs, which exposes an api that can stop this client and read its token.')
    }
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

<style scoped>
.client-settings {
  padding: 4px 0;
}
.page-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 16px;
}
.page-title {
  margin: 0 0 4px;
  font-size: 20px;
}
.page-subtitle,
.hint {
  margin: 0 0 8px;
  font-size: 12px;
  color: var(--text-muted, #909399);
  max-width: 720px;
}
.risky {
  color: var(--el-color-warning, #e6a23c);
  font-size: 13px;
}
</style>
