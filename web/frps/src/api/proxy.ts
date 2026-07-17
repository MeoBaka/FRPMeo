import { buildQueryString, http } from './http'
import { formatUnixSeconds } from '../utils/format'
import type { V2Page } from './http'
import type {
  ProxyListV2Params,
  ProxyStatsInfo,
  ProxyV2Info,
  ProxyV2Spec,
  ProxyV2SpecBlocks,
  ProxyV2Type,
  TrafficResponse,
} from '../types/proxy'

export interface SystemPruneResponse {
  type: 'offline_proxies'
  cleared: number
  total: number
}

export const getProxiesV2 = async (params: ProxyListV2Params = {}) => {
  const page = await http.getV2<V2Page<ProxyV2Info>>(
    `../api/v2/proxies${buildQueryString({
      page: params.page,
      pageSize: params.pageSize,
      status:
        params.status && params.status !== 'all' ? params.status : undefined,
      q: params.q || undefined,
      type: params.type || undefined,
      user: params.user,
      clientID: params.clientID || undefined,
    })}`,
  )

  return {
    ...page,
    items: page.items.map(toLegacyProxyStats),
  }
}

const getActiveProxySpec = (
  spec: ProxyV2Spec,
): ProxyV2SpecBlocks[ProxyV2Type] | undefined => {
  switch (spec.type) {
    case 'tcp':
      return spec.tcp
    case 'udp':
      return spec.udp
    case 'http':
      return spec.http
    case 'https':
      return spec.https
    case 'tcpmux':
      return spec.tcpmux
    case 'stcp':
      return spec.stcp
    case 'sudp':
      return spec.sudp
    case 'xtcp':
      return spec.xtcp
    case 'xudp':
      return spec.xudp
    case 'tcp+udp':
      return spec['tcp+udp']
    case 'stcp+sudp':
      return spec['stcp+sudp']
    case 'xtcp+xudp':
      return spec['xtcp+xudp']
    case 'mc':
      return spec.mc
    case 'pe':
      return spec.pe
    default:
      return assertNever(spec)
  }
}

// A proxy type the dashboard does not know about must not take the page down:
// frps may be newer than the bundled UI, and an unrenderable spec is far better
// than an empty proxy list.
const assertNever = (value: never): undefined => {
  console.warn('Unsupported proxy spec:', value)
  return undefined
}

export const toLegacyProxyStats = (proxy: ProxyV2Info): ProxyStatsInfo => {
  const type = proxy.spec.type
  const activeSpec = getActiveProxySpec(proxy.spec)

  return {
    name: proxy.name,
    type,
    conf: proxy.status.phase === 'offline' ? null : activeSpec,
    user: proxy.user,
    clientID: proxy.clientID,
    todayTrafficIn: proxy.status.todayTrafficIn,
    todayTrafficOut: proxy.status.todayTrafficOut,
    curConns: proxy.status.curConns,
    lastStartTime: formatUnixSeconds(proxy.status.lastStartAt),
    lastCloseTime: formatUnixSeconds(proxy.status.lastCloseAt),
    status: proxy.status.phase,
  }
}

export const getProxyByNameV2 = async (name: string) => {
  const proxy = await http.getV2<ProxyV2Info>(
    `../api/v2/proxies/${encodeURIComponent(name)}`,
  )
  return toLegacyProxyStats(proxy)
}

export const getProxyTraffic = (name: string) => {
  return http.getV2<TrafficResponse>(
    `../api/v2/proxies/${encodeURIComponent(name)}/traffic`,
  )
}

export const clearOfflineProxies = () => {
  return http.postV2<SystemPruneResponse>(
    '../api/v2/system/prune?type=offline_proxies',
  )
}
