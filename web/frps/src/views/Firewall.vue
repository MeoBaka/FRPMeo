<template>
  <div class="firewall-page" v-loading="loading">
    <div class="page-head">
      <div>
        <h1 class="page-title">Firewall</h1>
        <p class="page-subtitle">
          Native access control by source IP and destination port. Order: manual rules -> reputation provider
          (optional) -> default policy. frps queries the provider; it does not
          host a blocklist itself.
        </p>
      </div>
      <div class="enable-box">
        <span>Enabled</span>
        <el-switch v-model="snap.enabled" @change="save" />
      </div>
    </div>

    <!-- Scope -->
    <el-card class="section" shadow="never">
      <div class="card-title">Scope</div>
      <p class="hint">
        Rules match the source IP and the frps port it connects to (tcp, udp,
        http, https, mc, pe, tcpmux, tcp+udp). A port belongs to one proxy at a
        time, so a rule survives a proxy being re-registered under a new name.
        Note that http / https proxies share the vhost port and mc proxies may
        share a port, so a rule there covers all of them. stcp / xtcp and their
        udp variants are visitor-authenticated and are not covered.
      </p>
      <div class="fg-inline" style="margin-top:12px">
        <label>Also protect the frps control port</label>
        <el-switch v-model="snap.controlPort" @change="save" />
        <span class="hint">
          Applies rules to frpc clients connecting to bindPort, before login -
          name that port in a rule to block a client from logging in. Careful:
          with default policy "deny" this locks out every client that has no
          explicit allow rule.
        </span>
      </div>
    </el-card>

    <!-- Reputation provider -->
    <el-card class="section" shadow="never">
      <div class="card-title">Blacklist provider (for unknown IPs)</div>
      <div class="bar">
        <el-select v-model="snap.provider.mode" class="w220">
          <el-option label="Off (rules + default only)" value="off" />
          <el-option label="FRPControl" value="frpcontrol" />
          <el-option label="Custom API" value="custom" />
        </el-select>
        <span class="hint">frps asks this API whether an unknown source IP is blacklisted (cached).</span>
      </div>

      <!-- FRPControl: only URL + key -->
      <div v-if="snap.provider.mode === 'frpcontrol'" class="field-grid">
        <div class="fg-wide">
          <label>FRPControl URL (base)</label>
          <el-input v-model="snap.provider.frpControlURL" placeholder="https://frpcontrol.example.com:7002" />
        </div>
        <div class="fg-wide">
          <label>API key</label>
          <el-input v-model="snap.provider.frpControlAPIKey" placeholder="fwk_xxx" show-password />
        </div>
        <p class="hint fg-wide">frps calls POST {url}/api/fw/check with header X-API-Key and reads results.0.blacklisted.</p>
      </div>

      <!-- Custom -->
      <div v-else-if="snap.provider.mode === 'custom'" class="field-grid">
        <div class="fg-wide">
          <label>URL ({ip} placeholder)</label>
          <el-input v-model="snap.provider.url" placeholder="https://host/api/check?ip={ip}" />
        </div>
        <div>
          <label>Method</label>
          <el-select v-model="snap.provider.method" class="w120">
            <el-option label="GET" value="GET" /><el-option label="POST" value="POST" />
          </el-select>
        </div>
        <div v-if="snap.provider.method === 'POST'" class="fg-wide">
          <label>POST body ({ip})</label>
          <el-input v-model="snap.provider.body" placeholder='{"ips":["{ip}"]}' />
        </div>
        <div class="fg-wide">
          <label>Headers (one "Key: value" per line)</label>
          <el-input v-model="headersText" type="textarea" :rows="2" placeholder="X-API-Key: fwk_xxx" />
        </div>
        <div class="fg-wide">
          <label>Blocked JSON path (dot, supports {ip} + array index)</label>
          <el-input v-model="snap.provider.blockedPath" placeholder="results.0.blacklisted" />
        </div>
      </div>

      <!-- common (frpcontrol / custom) -->
      <div v-if="snap.provider.mode !== 'off'" class="field-grid" style="margin-top:12px">
        <div><label>Cache TTL (s)</label><el-input v-model.number="snap.provider.cacheTTLSec" type="number" placeholder="300" /></div>
        <div><label>Timeout (ms)</label><el-input v-model.number="snap.provider.timeoutMs" type="number" placeholder="800" /></div>
        <div class="fg-inline"><label>Fail-open</label><el-switch v-model="snap.provider.failOpen" /><span class="hint">off = block on error</span></div>
        <div class="fg-inline"><label>Insecure TLS</label><el-switch v-model="snap.provider.insecureTLS" /><span class="hint">self-signed https</span></div>
      </div>

      <!-- The provider form is free text, so it saves on demand rather than on
           every keystroke. Everything else on this page applies on change. -->
      <div class="bar" style="margin-top:12px">
        <div class="grow" />
        <el-button type="primary" :loading="saving" @click="save">Save provider</el-button>
      </div>
    </el-card>

    <!-- Manual rules -->
    <el-card class="section" shadow="never">
      <div class="bar">
        <div class="field">
          <label>Default policy</label>
          <el-select v-model="snap.default" class="w120" @change="save">
            <el-option label="allow" value="allow" /><el-option label="deny" value="deny" />
          </el-select>
        </div>
        <div class="grow" />
        <span class="hint">Every change here applies immediately.</span>
        <el-button type="primary" @click="openAdd">Add rule</el-button>
      </div>
      <el-table :data="pagedRules" empty-text="No manual rules - provider + default policy apply">
        <el-table-column label="Action" width="90">
          <template #default="{ row }">
            <el-tag :type="row.action === 'allow' ? 'success' : 'danger'" disable-transitions>{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="CIDR / IP" min-width="130"><template #default="{ row }">{{ row.cidr || 'any' }}</template></el-table-column>
        <el-table-column label="Port" min-width="120"><template #default="{ row }">{{ row.port || 'all' }}</template></el-table-column>
        <el-table-column label="Expires" min-width="110"><template #default="{ row }">{{ expiryText(row.expiresAt) }}</template></el-table-column>
        <el-table-column label="Note" prop="note" min-width="120" />
        <el-table-column label="" width="170" align="right">
          <!-- $index is the row's position on this page; rules are matched in
               order across the whole list, so map it back before touching. -->
          <template #default="{ $index }">
            <el-button size="small" @click="moveUp(rowIndex($index))" :disabled="rowIndex($index) === 0">Up</el-button>
            <el-button size="small" @click="openEdit(rowIndex($index))">Edit</el-button>
            <el-button size="small" type="danger" @click="removeRule(rowIndex($index))">Del</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination
        v-if="snap.rules.length > pageSize"
        class="pager"
        layout="total, sizes, prev, pager, next"
        :total="snap.rules.length"
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        background
      />
    </el-card>

    <!-- Add/Edit rule dialog -->
    <el-dialog v-model="dialog.open" :title="dialog.index === -1 ? 'Add rule' : 'Edit rule'" width="480px">
      <el-form label-width="100px">
        <el-form-item label="Action">
          <el-select v-model="dialog.rule.action"><el-option label="allow" value="allow" /><el-option label="deny" value="deny" /></el-select>
        </el-form-item>
        <el-form-item label="CIDR / IP"><el-input v-model="dialog.rule.cidr" placeholder="1.2.3.0/24, ::1, 1.2.3.4 (blank=any)" /></el-form-item>
        <el-form-item label="Port">
          <el-input v-model="dialog.rule.port" placeholder="all" />
          <div class="hint" style="margin-top:4px">
            The frps port the client connects to: a single port (6000), a lo-hi
            range (6000-6010), a list (80,443,7000-7010), or all. Left blank it
            becomes all.
          </div>
        </el-form-item>
        <el-form-item label="Duration">
          <el-select v-model="dialog.duration" class="w160">
            <el-option label="Permanent" value="perm" /><el-option label="14 days" value="14" /><el-option label="Custom days" value="custom" />
          </el-select>
          <el-input v-if="dialog.duration === 'custom'" v-model.number="dialog.days" type="number" class="w90" style="margin-left:8px" />
        </el-form-item>
        <el-form-item label="Note"><el-input v-model="dialog.rule.note" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog.open = false">Cancel</el-button>
        <el-button type="primary" @click="applyDialog">OK</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { http } from '../api/http'

interface Rule { id?: string; action: string; cidr: string; port: string; note: string; expiresAt?: number }
interface Provider {
  mode: string
  frpControlURL: string; frpControlAPIKey: string
  url: string; method: string; body: string; headers: Record<string, string>; blockedPath: string
  cacheTTLSec: number; timeoutMs: number; failOpen: boolean; insecureTLS: boolean
}
interface Snap { enabled: boolean; controlPort: boolean; default: string; rules: Rule[]; provider: Provider }

function defProvider(): Provider {
  return { mode: 'off', frpControlURL: '', frpControlAPIKey: '', url: '', method: 'GET', body: '', headers: {}, blockedPath: '', cacheTTLSec: 300, timeoutMs: 800, failOpen: false, insecureTLS: false }
}

const loading = ref(false)
const saving = ref(false)
const snap = reactive<Snap>({ enabled: true, controlPort: false, default: 'allow', rules: [], provider: defProvider() })

const headersText = computed({
  get: () => Object.entries(snap.provider.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n'),
  set: (t: string) => {
    const h: Record<string, string> = {}
    for (const line of t.split('\n')) {
      const i = line.indexOf(':')
      if (i > 0) h[line.slice(0, i).trim()] = line.slice(i + 1).trim()
    }
    snap.provider.headers = h
  },
})

const dialog = reactive<{ open: boolean; index: number; rule: Rule; duration: string; days: number }>({
  open: false, index: -1, rule: { action: 'deny', cidr: '', port: 'all', note: '' }, duration: '14', days: 14,
})

const page = ref(1)
const pageSize = ref(10)

const pagedRules = computed(() => {
  // Deleting the last row of the last page would otherwise strand us on an
  // empty page.
  const pages = Math.max(1, Math.ceil(snap.rules.length / pageSize.value))
  if (page.value > pages) page.value = pages
  const start = (page.value - 1) * pageSize.value
  return snap.rules.slice(start, start + pageSize.value)
})

// Row position on the current page -> position in the full, ordered rule list.
const rowIndex = (i: number) => (page.value - 1) * pageSize.value + i

function expiryText(exp?: number) {
  if (!exp) return 'permanent'
  const d = Math.round((exp - Date.now() / 1000) / 86400)
  return d <= 0 ? 'expired' : `${d}d`
}

async function load() {
  loading.value = true
  try {
    const s = await http.get<Snap>('../api/firewall')
    snap.enabled = s.enabled
    snap.controlPort = !!s.controlPort
    snap.default = s.default || 'allow'
    snap.rules = s.rules || []
    snap.provider = { ...defProvider(), ...(s.provider || {}) }
    if (!snap.provider.mode) snap.provider.mode = 'off'
    if (!snap.provider.headers) snap.provider.headers = {}
  } catch (e: any) {
    ElMessage.error('Load failed: ' + (e.message || e))
  } finally {
    loading.value = false
  }
}

// persist pushes the whole config and reports whether frps took it. Returns
// false on rejection (a bad port spec, say) so callers can undo rather than
// leave the table showing a rule that is not actually in force.
async function persist(okMsg: string) {
  saving.value = true
  try {
    await http.put('../api/firewall', { enabled: snap.enabled, controlPort: snap.controlPort, default: snap.default, rules: snap.rules, provider: snap.provider })
    ElMessage.success(okMsg)
    return true
  } catch (e: any) {
    ElMessage.error('Save failed: ' + (e.message || e))
    return false
  } finally {
    saving.value = false
  }
}

const save = () => persist('Saved')

// Rule edits take effect on the spot. A rule list that needed a separate Save
// would be a trap in the other direction too: deleting a rule and walking away
// while it is still blocking traffic.
async function applyRules(okMsg: string, undo: Rule[]) {
  if (!(await persist(okMsg))) {
    snap.rules = undo
  }
}

function openAdd() {
  dialog.index = -1
  dialog.rule = { action: 'deny', cidr: '', port: 'all', note: '' }
  dialog.duration = '14'; dialog.days = 14
  dialog.open = true
}
function openEdit(i: number) {
  dialog.index = i
  dialog.rule = { ...snap.rules[i], port: snap.rules[i].port || 'all' }
  const exp = snap.rules[i].expiresAt
  dialog.duration = !exp ? 'perm' : 'custom'
  dialog.days = exp ? Math.max(1, Math.round((exp - Date.now() / 1000) / 86400)) : 14
  dialog.open = true
}
async function applyDialog() {
  const r = { ...dialog.rule }
  // Blank means every port; say so, rather than leaving the rule looking unset.
  r.port = r.port.trim() || 'all'
  if (dialog.duration === 'perm') r.expiresAt = 0
  else {
    const days = dialog.duration === '14' ? 14 : dialog.days || 1
    r.expiresAt = Math.floor(Date.now() / 1000) + days * 86400
  }
  const undo = snap.rules.slice()
  if (dialog.index === -1) snap.rules.push(r)
  else snap.rules[dialog.index] = r
  dialog.open = false
  await applyRules(dialog.index === -1 ? 'Rule added and applied' : 'Rule updated and applied', undo)
}
async function removeRule(i: number) {
  const r = snap.rules[i]
  const what = `${r.action} ${r.cidr || 'any IP'} on port ${r.port || 'all'}`
  try {
    await ElMessageBox.confirm(
      `Delete this rule? It stops applying straight away.\n\n${what}`,
      'Delete rule',
      { type: 'warning', confirmButtonText: 'Delete', confirmButtonClass: 'el-button--danger', cancelButtonText: 'Cancel' },
    )
  } catch {
    return // dismissed
  }
  const undo = snap.rules.slice()
  snap.rules.splice(i, 1)
  await applyRules('Rule removed', undo)
}
async function moveUp(i: number) {
  if (i === 0) return
  const undo = snap.rules.slice()
  const r = snap.rules.splice(i, 1)[0]
  snap.rules.splice(i - 1, 0, r)
  await applyRules('Order updated', undo)
}

onMounted(load)
</script>

<style scoped>
.page-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
.enable-box { display: flex; align-items: center; gap: 8px; font-size: 14px; }
.section { margin-bottom: 16px; }
.card-title { font-weight: 600; margin-bottom: 12px; }
.bar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.grow { flex: 1; }
.field { display: flex; flex-direction: column; gap: 6px; }
.pager { margin-top: 12px; display: flex; justify-content: flex-end; }
.field label, .field-grid label, .fg-inline label { font-size: 12px; color: var(--text-muted, #909399); }
.hint { font-size: 12px; color: var(--text-muted, #909399); margin: 0; }
.w120 { width: 120px; } .w160 { width: 160px; } .w220 { width: 220px; } .w90 { width: 90px; }
.field-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.fg-wide { grid-column: 1 / -1; display: flex; flex-direction: column; gap: 6px; }
.field-grid > div:not(.fg-wide):not(.fg-inline) { display: flex; flex-direction: column; gap: 6px; }
.fg-inline { display: flex; align-items: center; gap: 8px; }
</style>
