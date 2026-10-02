class BaseProxy {
  name: string
  type: string
  annotations: Map<string, string>
  encryption: boolean
  compression: boolean
  conns: number
  trafficIn: number
  trafficOut: number
  lastStartTime: string
  lastCloseTime: string
  status: string
  user: string
  clientID: string
  addr: string
  port: number

  customDomains: string
  hostHeaderRewrite: string
  locations: string
  subdomain: string

  // TCPMux specific
  multiplexer: string
  routeByHTTPUser: string

  // Secure access summary; empty when it is off
  secure: string

  constructor(proxyStats: any) {
    this.name = proxyStats.name
    this.type = ''
    this.annotations = new Map<string, string>()
    if (proxyStats.conf?.annotations) {
      for (const key in proxyStats.conf.annotations) {
        this.annotations.set(key, proxyStats.conf.annotations[key])
      }
    }

    this.encryption = false
    this.compression = false
    this.encryption =
      proxyStats.conf?.transport?.useEncryption || this.encryption
    this.compression =
      proxyStats.conf?.transport?.useCompression || this.compression
    this.conns = proxyStats.curConns
    this.trafficIn = proxyStats.todayTrafficIn
    this.trafficOut = proxyStats.todayTrafficOut
    this.lastStartTime = proxyStats.lastStartTime
    this.lastCloseTime = proxyStats.lastCloseTime
    this.status = proxyStats.status
    this.user = proxyStats.user || ''
    this.clientID = proxyStats.clientID || ''

    this.addr = ''
    this.port = 0
    this.customDomains = ''
    this.hostHeaderRewrite = ''
    this.locations = ''
    this.subdomain = ''
    this.multiplexer = ''
    this.routeByHTTPUser = ''
    this.secure = describeSecure(proxyStats.conf?.secure)
  }
}

// How each secure method reads in the summary. "http" is header, form and json
// together, the first version's single switch.
const SECURE_METHOD_LABELS: Record<string, string> = {
  link: 'link',
  basic: 'sign-in prompt',
  header: 'header',
  form: 'POST form',
  json: 'POST JSON',
  bearer: 'bearer token',
  http: 'header / POST',
  line: 'first line',
}

// describeSecure sums up a proxy's secure access settings in one line. frps
// never sends the key itself, only that there is one.
function describeSecure(s: any): string {
  if (!s?.enable) return ''
  // An empty list is what frps defaults to: link, http and line.
  const methods: string[] =
    Array.isArray(s.methods) && s.methods.length > 0
      ? s.methods
      : ['link', 'http', 'line']
  const hours = (s.unlockSeconds || 43200) / 3600
  const parts = [
    `title "${s.title}"`,
    methods.map((m) => SECURE_METHOD_LABELS[m] || m).join(', '),
    `unlock ${Number.isInteger(hours) ? hours : hours.toFixed(1)}h`,
  ]
  if (s.allowIPs?.length) parts.push(`${s.allowIPs.length} allowed IP(s)`)
  if (s.trustedIPs?.length) parts.push(`${s.trustedIPs.length} trusted IP(s)`)
  return parts.join(' · ')
}

class TCPProxy extends BaseProxy {
  constructor(proxyStats: any) {
    super(proxyStats)
    this.type = 'tcp'
    if (proxyStats.conf != null) {
      this.addr = ':' + proxyStats.conf.remotePort
      this.port = proxyStats.conf.remotePort
    } else {
      this.addr = ''
      this.port = 0
    }
  }
}

class UDPProxy extends BaseProxy {
  constructor(proxyStats: any) {
    super(proxyStats)
    this.type = 'udp'
    if (proxyStats.conf != null) {
      this.addr = ':' + proxyStats.conf.remotePort
      this.port = proxyStats.conf.remotePort
    } else {
      this.addr = ''
      this.port = 0
    }
  }
}

class HTTPProxy extends BaseProxy {
  constructor(proxyStats: any, port: number, subdomainHost: string) {
    super(proxyStats)
    this.type = 'http'
    this.port = port
    if (proxyStats.conf) {
      this.customDomains = proxyStats.conf.customDomains || this.customDomains
      this.hostHeaderRewrite = proxyStats.conf.hostHeaderRewrite
      this.locations = proxyStats.conf.locations
      if (proxyStats.conf.subdomain) {
        this.subdomain = `${proxyStats.conf.subdomain}.${subdomainHost}`
      }
    }
  }
}

class HTTPSProxy extends BaseProxy {
  constructor(proxyStats: any, port: number, subdomainHost: string) {
    super(proxyStats)
    this.type = 'https'
    this.port = port
    if (proxyStats.conf != null) {
      this.customDomains = proxyStats.conf.customDomains || this.customDomains
      if (proxyStats.conf.subdomain) {
        this.subdomain = `${proxyStats.conf.subdomain}.${subdomainHost}`
      }
    }
  }
}

class TCPMuxProxy extends BaseProxy {
  constructor(proxyStats: any, port: number, subdomainHost: string) {
    super(proxyStats)
    this.type = 'tcpmux'
    this.port = port

    if (proxyStats.conf) {
      this.customDomains = proxyStats.conf.customDomains || this.customDomains
      this.multiplexer = proxyStats.conf.multiplexer || ''
      this.routeByHTTPUser = proxyStats.conf.routeByHTTPUser || ''
      if (proxyStats.conf.subdomain) {
        this.subdomain = `${proxyStats.conf.subdomain}.${subdomainHost}`
      }
    }
  }
}

class STCPProxy extends BaseProxy {
  constructor(proxyStats: any) {
    super(proxyStats)
    this.type = 'stcp'
  }
}

class SUDPProxy extends BaseProxy {
  constructor(proxyStats: any) {
    super(proxyStats)
    this.type = 'sudp'
  }
}

export {
  BaseProxy,
  TCPProxy,
  UDPProxy,
  TCPMuxProxy,
  HTTPProxy,
  HTTPSProxy,
  STCPProxy,
  SUDPProxy,
}
