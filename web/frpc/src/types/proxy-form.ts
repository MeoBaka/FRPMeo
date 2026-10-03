import type { ProxyType, VisitorType } from './constants'

export interface ProxyFormData {
  // Base fields (ProxyBaseConfig)
  name: string
  type: ProxyType
  enabled: boolean

  // Backend (ProxyBackend)
  localIP: string
  localPort: number | undefined
  localPortUDP: number | undefined
  pluginType: string
  pluginConfig: Record<string, any>

  // Transport (ProxyTransport)
  useEncryption: boolean
  useCompression: boolean
  bandwidthLimit: string
  bandwidthLimitMode: string
  proxyProtocolVersion: string

  // Load Balancer (LoadBalancerConfig)
  loadBalancerGroup: string
  loadBalancerGroupKey: string

  // Health Check (HealthCheckConfig)
  healthCheckType: string
  healthCheckTimeoutSeconds: number | undefined
  healthCheckMaxFailed: number | undefined
  healthCheckIntervalSeconds: number | undefined
  healthCheckPath: string
  healthCheckHTTPHeaders: Array<{ name: string; value: string }>

  // Metadata & Annotations
  metadatas: Array<{ key: string; value: string }>
  annotations: Array<{ key: string; value: string }>

  // TCP/UDP specific
  remotePort: number | undefined

  // Domain (HTTP/HTTPS/TCPMux) - DomainConfig
  customDomains: string[]
  subdomain: string

  // HTTP specific (HTTPProxyConfig)
  locations: string[]
  httpUser: string
  httpPassword: string
  hostHeaderRewrite: string
  requestHeaders: Array<{ key: string; value: string }>
  responseHeaders: Array<{ key: string; value: string }>
  routeByHTTPUser: string

  // TCPMux specific
  multiplexer: string

  // STCP/SUDP/XTCP specific
  secretKey: string
  allowUsers: string[]

  // XTCP specific (NatTraversalConfig)
  natTraversalDisableAssistedAddrs: boolean

  // MC/PE specific (fork Minecraft types): pe hostname -> local backend map
  forcedHosts: Array<{ key: string; value: string }>

  // Secure access (SecureConfig) - every type in SECURE_PROXY_TYPES. One
  // switch per way of presenting the key; secure.methods is built from them.
  secureEnable: boolean
  // The first login is title and key; the rest are secure.credentials.
  secureTitle: string
  secureKey: string
  secureCredentials: Array<{ title: string; key: string }>
  secureMethodLink: boolean
  secureMethodBasic: boolean
  secureMethodHeader: boolean
  secureMethodForm: boolean
  secureMethodJSON: boolean
  secureMethodBearer: boolean
  secureMethodLine: boolean
  secureUnlockSeconds: number
  secureAllowIPs: string[]
  secureTrustedIPs: string[]
  secureMaxFailures: number | undefined
  secureMaxAttemptsPerMinute: number | undefined
  secureBanSeconds: number | undefined
}

// The proxy types secure access applies to. The visitor types (stcp, xtcp and
// friends) already make every caller prove a secretKey, so frps rejects it
// there.
export const SECURE_PROXY_TYPES: ProxyType[] = [
  'tcp',
  'udp',
  'http',
  'https',
  'tcpmux',
  'tcp+udp',
  'mc',
  'pe',
]

// secureLineApplies reports whether visitors of this type can send the key as
// the first line (or, for udp and pe, as a datagram). frps only ever sees an
// HTTP request or a TLS stream on http and https, and routes mc by the hostname
// in the handshake, which a key line lacks - it rejects the method on all three.
export function secureLineApplies(type: ProxyType): boolean {
  return type !== 'http' && type !== 'https' && type !== 'mc'
}

// secureAnyMethod reports whether at least one way of presenting the key is on
// for this type. With none, frps would read the empty list as the defaults.
export function secureAnyMethod(f: ProxyFormData): boolean {
  return (
    f.secureMethodLink ||
    f.secureMethodBasic ||
    f.secureMethodHeader ||
    f.secureMethodForm ||
    f.secureMethodJSON ||
    f.secureMethodBearer ||
    (f.secureMethodLine && secureLineApplies(f.type))
  )
}

export interface VisitorFormData {
  // Base fields (VisitorBaseConfig)
  name: string
  type: VisitorType
  enabled: boolean

  // Transport (VisitorTransport)
  useEncryption: boolean
  useCompression: boolean

  // Connection
  secretKey: string
  serverUser: string
  serverName: string
  bindAddr: string
  bindPort: number | undefined

  // XTCP specific (XTCPVisitorConfig)
  protocol: string
  keepTunnelOpen: boolean
  maxRetriesAnHour: number | undefined
  minRetryInterval: number | undefined
  fallbackTo: string
  fallbackTimeoutMs: number | undefined
  natTraversalDisableAssistedAddrs: boolean

  // Plugin (visitor plugin, e.g. virtual_net)
  pluginType: string
  pluginConfig: Record<string, any>
}

export function createDefaultProxyForm(): ProxyFormData {
  return {
    name: '',
    type: 'tcp',
    enabled: true,

    localIP: '127.0.0.1',
    localPort: undefined,
    pluginType: '',
    pluginConfig: {},

    useEncryption: false,
    useCompression: false,
    bandwidthLimit: '',
    bandwidthLimitMode: 'client',
    proxyProtocolVersion: '',

    loadBalancerGroup: '',
    loadBalancerGroupKey: '',

    healthCheckType: '',
    healthCheckTimeoutSeconds: undefined,
    healthCheckMaxFailed: undefined,
    healthCheckIntervalSeconds: undefined,
    healthCheckPath: '',
    healthCheckHTTPHeaders: [],

    metadatas: [],
    annotations: [],

    remotePort: undefined,

    customDomains: [],
    subdomain: '',

    locations: [],
    httpUser: '',
    httpPassword: '',
    hostHeaderRewrite: '',
    requestHeaders: [],
    responseHeaders: [],
    routeByHTTPUser: '',

    multiplexer: 'httpconnect',

    secretKey: '',
    allowUsers: [],
    localPortUDP: undefined,
    forcedHosts: [],

    natTraversalDisableAssistedAddrs: false,

    secureEnable: false,
    secureTitle: '',
    secureKey: '',
    secureCredentials: [],
    // The defaults are what frps reads an empty list as. The sign-in prompt
    // and bearer tokens are only on when chosen.
    secureMethodLink: true,
    secureMethodBasic: false,
    secureMethodHeader: true,
    secureMethodForm: true,
    secureMethodJSON: true,
    secureMethodBearer: false,
    secureMethodLine: true,
    secureUnlockSeconds: 0,
    secureAllowIPs: [],
    secureTrustedIPs: [],
    secureMaxFailures: undefined,
    secureMaxAttemptsPerMinute: undefined,
    secureBanSeconds: undefined,
  }
}

export function createDefaultVisitorForm(): VisitorFormData {
  return {
    name: '',
    type: 'stcp',
    enabled: true,

    useEncryption: false,
    useCompression: false,

    secretKey: '',
    serverUser: '',
    serverName: '',
    bindAddr: '127.0.0.1',
    bindPort: undefined,

    protocol: 'quic',
    keepTunnelOpen: false,
    maxRetriesAnHour: undefined,
    minRetryInterval: undefined,
    fallbackTo: '',
    fallbackTimeoutMs: undefined,
    natTraversalDisableAssistedAddrs: false,

    pluginType: '',
    pluginConfig: {},
  }
}
