<template>
  <ConfigSection title="Secure Access" collapsible :readonly="readonly" :has-value="form.secureEnable">
    <ConfigField label="Enable Secure Access" type="switch" v-model="form.secureEnable"
      tip="Visitors must present the key before frps forwards anything" :readonly="readonly" />

    <template v-if="form.secureEnable">
      <div class="field-row two-col">
        <ConfigField label="Custom Title" type="text" v-model="form.secureTitle" prop="secureTitle"
          placeholder="dangnhap" tip="Name the key travels under, e.g. auth or dangnhap" :readonly="readonly" />
        <div class="secure-key-row">
          <ConfigField label="Custom Desc (Key)" type="password" v-model="form.secureKey" prop="secureKey"
            placeholder="6-256 characters" class="field-grow" :readonly="readonly" />
          <ActionButton v-if="!readonly" variant="outline" size="small" class="secure-generate" @click="generateKey">
            Generate
          </ActionButton>
        </div>
      </div>

      <div class="secure-ways-title">Ways to present the key - choose one or more</div>
      <div class="field-row three-col">
        <ConfigField label="Link (GET ?title=key)" type="switch" v-model="form.secureMethodLink" prop="secureMethodLink"
          tip="Open once to unlock your IP" :readonly="readonly" />
        <ConfigField label="Sign-in Prompt" type="switch" v-model="form.secureMethodBasic"
          tip="Opening the address asks: username = title, password = key" :readonly="readonly" />
        <ConfigField v-if="lineApplies" label="First Line (raw TCP / UDP)" type="switch"
          v-model="form.secureMethodLine" tip="Custom clients send it first" :readonly="readonly" />
      </div>

      <div class="secure-ways-title">HTTP request - for scripts and apps</div>
      <div class="field-row three-col">
        <ConfigField label="Header" type="switch" v-model="form.secureMethodHeader"
          tip="title: key, on any method" :readonly="readonly" />
        <ConfigField label="POST Form" type="switch" v-model="form.secureMethodForm"
          tip="title=key in a form body" :readonly="readonly" />
        <ConfigField label="POST JSON" type="switch" v-model="form.secureMethodJSON"
          tip='{"title": "key"} as the body' :readonly="readonly" />
      </div>
      <div class="field-row three-col">
        <ConfigField label="Bearer Token" type="switch" v-model="form.secureMethodBearer"
          tip="Authorization: Bearer key - API clients' API key" :readonly="readonly" />
      </div>

      <div class="field-row three-col">
        <ConfigField label="Unlock Duration" type="select" v-model="form.secureUnlockSeconds"
          :options="unlockOptions" :readonly="readonly" />
      </div>

      <div class="field-row two-col">
        <ConfigField label="Allowed IPs" type="tags" v-model="form.secureAllowIPs" placeholder="1.2.3.4 or 10.0.0.0/8"
          tip="If set, only these IPs may connect - and they still need the key" :readonly="readonly" />
        <ConfigField label="Trusted IPs" type="tags" v-model="form.secureTrustedIPs" placeholder="1.2.3.4"
          tip="These IPs connect without the key" :readonly="readonly" />
      </div>

      <div class="field-row three-col">
        <ConfigField label="Max Wrong Keys" type="number" v-model="form.secureMaxFailures" placeholder="5"
          tip="Ban after this many; -1 turns it off" :min="-1" :readonly="readonly" />
        <ConfigField label="Max Attempts / Minute" type="number" v-model="form.secureMaxAttemptsPerMinute"
          placeholder="30" tip="Ban a source trying faster; -1 turns it off" :min="-1" :readonly="readonly" />
        <ConfigField label="Ban Duration (seconds)" type="number" v-model="form.secureBanSeconds" placeholder="600"
          tip="Default 600 (10 minutes)" :min="0" :readonly="readonly" />
      </div>

      <div v-if="usage.length > 0" class="secure-usage">
        <div class="secure-usage-title">How visitors get in</div>
        <div v-for="item in usage" :key="item.label" class="secure-usage-row">
          <span class="secure-usage-label">{{ item.label }}</span>
          <code class="secure-usage-code">{{ item.display }}</code>
          <ActionButton variant="outline" size="small" @click="copy(item.value)">Copy</ActionButton>
        </div>
        <div class="secure-usage-note">{{ usageNote }}</div>
      </div>
    </template>
  </ConfigSection>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { secureLineApplies, type ProxyFormData } from '../../types'
import ActionButton from '@shared/components/ActionButton.vue'
import ConfigSection from '../ConfigSection.vue'
import ConfigField from '../ConfigField.vue'

const props = withDefaults(defineProps<{
  modelValue: ProxyFormData
  readonly?: boolean
  // The proxy's public address from the status API, when known.
  remoteAddr?: string
}>(), { readonly: false, remoteAddr: '' })

const emit = defineEmits<{ 'update:modelValue': [value: ProxyFormData] }>()

const form = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

// Letters and digits without the look-alikes (0/O, 1/l/I), so a key read out
// loud or copied by hand survives, and nothing in it needs escaping in a URL.
const KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
const KEY_LENGTH = 20

const generateKey = () => {
  const bytes = new Uint32Array(KEY_LENGTH)
  crypto.getRandomValues(bytes)
  form.value.secureKey = Array.from(bytes, (b) => KEY_ALPHABET[b % KEY_ALPHABET.length]).join('')
}

// Switching secure access on for the first time leaves a working setup behind
// rather than two empty required fields.
watch(
  () => form.value.secureEnable,
  (on) => {
    if (!on || props.readonly) return
    if (!form.value.secureTitle) form.value.secureTitle = 'auth'
    if (!form.value.secureKey) generateKey()
  },
)

const UNLOCK_PRESETS = [
  { label: 'Default (12 hours)', value: 0 },
  { label: '1 hour', value: 3600 },
  { label: '6 hours', value: 21600 },
  { label: '12 hours', value: 43200 },
  { label: '1 day', value: 86400 },
  { label: '7 days', value: 604800 },
  { label: '30 days', value: 2592000 },
]

// A value set in the config file that is not a preset still has to show up.
const unlockOptions = computed(() => {
  const v = form.value.secureUnlockSeconds
  if (UNLOCK_PRESETS.some((o) => o.value === v)) return UNLOCK_PRESETS
  return [...UNLOCK_PRESETS, { label: `${v} seconds`, value: v }]
})

const lineApplies = computed(() => secureLineApplies(form.value.type))
const UDP_TYPES = ['udp', 'pe']
// tcpmux is reached through frps' HTTP CONNECT port, so curl goes through it.
const TCPMUX_TUNNEL = '-p -x http://<frps-address>:<tcpmux-port> '

const domainOf = (f: ProxyFormData) =>
  f.customDomains.find(Boolean) ||
  (f.subdomain ? `${f.subdomain}.<subdomain-host>` : '<domain>')

// Where a visitor opens the unlock link. http, https and tcpmux proxies are
// reached by domain; mc by its hostname on the game port, which is what frps
// routes the request by; every other type answers the link on its own public
// port - a udp proxy through a tcp listener frps opens on the same number.
const linkBase = computed(() => {
  const f = form.value
  if (['http', 'https', 'tcpmux'].includes(f.type)) {
    return `http://${domainOf(f)}`
  }
  if (f.type === 'mc') {
    return `http://${domainOf(f)}:${f.remotePort ?? '<remote-port>'}`
  }
  let addr = props.remoteAddr || (f.remotePort != null ? `:${f.remotePort}` : ':<remote-port>')
  if (addr.startsWith(':')) addr = `<frps-address>${addr}`
  return `http://${addr}`
})

interface UsageItem {
  label: string
  display: string
  value: string
}

const usage = computed((): UsageItem[] => {
  const f = form.value
  const title = f.secureTitle || '<title>'
  const key = f.secureKey || '<key>'
  // The key is only ever shown masked; Copy puts the real one on the clipboard.
  const masked = f.secureKey ? '••••••' : '<key>'
  const base = linkBase.value
  const tunnel = f.type === 'tcpmux' ? TCPMUX_TUNNEL : ''
  const curl = (args: string) => `curl ${tunnel}${args}`
  const items: UsageItem[] = []
  const add = (label: string, cmd: (k: string) => string) =>
    items.push({ label, display: cmd(masked), value: cmd(key) })

  if (f.secureMethodLink) {
    const link = (k: string) => (tunnel ? curl(`"${base}/?${title}=${k}"`) : `${base}/?${title}=${k}`)
    items.push({ label: 'Link', display: link(masked), value: link(encodeURIComponent(key)) })
  }
  if (f.secureMethodBasic) {
    // A browser shows its own prompt for this address; a script passes the
    // same pair as a username and password.
    items.push({
      label: 'Sign-in prompt',
      display: `${base}/  (username: ${title}, password: ${masked})`,
      value: `${base}/`,
    })
    add('Sign-in (script)', (k) => curl(`-u "${title}:${k}" ${base}/`))
  }
  if (f.secureMethodHeader) add('Header', (k) => curl(`-H "${title}: ${k}" ${base}/`))
  if (f.secureMethodForm) add('POST form', (k) => curl(`-d "${title}=${k}" ${base}/`))
  if (f.secureMethodJSON) {
    add('POST JSON', (k) => curl(`-H "Content-Type: application/json" -d '{"${title}":"${k}"}' ${base}/`))
  }
  if (f.secureMethodBearer) add('Bearer token', (k) => curl(`-H "Authorization: Bearer ${k}" ${base}/`))
  if (f.secureMethodLine && lineApplies.value) {
    const line = (k: string) => `${title}: ${k}`
    items.push({
      label: UDP_TYPES.includes(f.type) ? 'UDP datagram' : 'First line',
      display: line(masked),
      value: line(key),
    })
  }
  return items
})

const usageNote = computed(() => {
  switch (form.value.type) {
    case 'http':
      return 'The link and the sign-in prompt unlock your IP (the link also sets a cookie); apps can send the header or a bearer token on every request instead.'
    case 'https':
      return 'TLS passes through frps untouched, so unlock over plain http:// on the frps HTTP port first.'
    case 'udp':
    case 'pe':
      return 'Unlock over http:// (frps answers it over TCP on the same port) or send the line as one datagram, then connect as usual.'
    case 'tcpmux':
      return 'The key travels inside the CONNECT tunnel; once your IP is unlocked, connect as usual.'
    case 'mc':
      return 'Unlock with the server hostname players type in the game, then join as usual.'
    default:
      return 'Once unlocked, any app from that IP - game, RDP, SSH - connects as usual for the unlock duration. A request with the bearer token goes straight through to the backend, for API clients.'
  }
})

const copy = async (text: string) => {
  try {
    // navigator.clipboard only exists on https or localhost; the dashboard is
    // often reached over plain http on a LAN address.
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
    } else {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    ElMessage.success('Copied')
  } catch {
    ElMessage.error('Copy failed')
  }
}
</script>

<style scoped lang="scss">
@use '@/assets/css/form-layout';

.secure-key-row {
  display: flex;
  align-items: flex-end;
  gap: 8px;
}

.secure-key-row .field-grow {
  flex: 1;
}

.secure-generate {
  margin-bottom: 2px;
}

.secure-ways-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--color-text-secondary);
}

.secure-usage {
  border: 1px solid var(--color-border-lighter);
  border-radius: 8px;
  padding: 12px 16px;
  background: var(--color-bg-tertiary);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.secure-usage-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--color-text-primary);
}

.secure-usage-row {
  display: grid;
  grid-template-columns: 110px 1fr auto;
  align-items: center;
  gap: 12px;
}

.secure-usage-label {
  font-size: 12px;
  color: var(--color-text-secondary);
}

.secure-usage-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  word-break: break-all;
  color: var(--color-text-primary);
}

.secure-usage-note {
  font-size: 12px;
  color: var(--color-text-muted);
}

@include mobile {
  .secure-usage-row {
    grid-template-columns: 1fr auto;
  }

  .secure-usage-label {
    grid-column: 1 / -1;
  }
}
</style>
