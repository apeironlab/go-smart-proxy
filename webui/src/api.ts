export interface RouteInfo {
  name: string
  gateway: string
  iface: string
  net: string
  pacUrl: string
  proxyUrl: string
  credential: string
  applicable: boolean
  whyNot: string
  pacStatus: string
  pacError: string
}

export interface Credential {
  name: string
  user: string
  password: string
}

export interface ConnEvent {
  time: string
  msg: string
}

export interface ConnInfo {
  id: number
  type: string
  client: string
  host: string
  target: string
  proxy: string
  route: string
  cred: string
  method: string
  url: string
  state: string
  auth: string
  status: number
  error: string
  started: string
  ended: string | null
  bytesClientIn: number
  bytesClientOut: number
  bytesUpIn: number
  bytesUpOut: number
  events: ConnEvent[]
}

export interface DnsEntry {
  host: string
  ip: string
}

export interface SystemProxyState {
  raw: string
  httpEnabled: boolean
  httpProxy: string
  httpPort: number
  httpsEnabled: boolean
  httpsProxy: string
  httpsPort: number
  pacEnabled: boolean
  pacUrl: string
  exceptions: string[]
  primaryService: string
  vpnService: string
  vpnHttpEnabled: boolean
  vpnHttpProxy: string
  vpnHttpPort: string
  vpnHttpsEnabled: boolean
  vpnHttpsProxy: string
  vpnHttpsPort: string
  vpnPacEnabled: boolean
}

export interface StateInfo {
  address: string
  iface: string
  gateway: string
  network: string
  forceRoute: string
  systemProxy: boolean
  systemProxyExclude: string[]
  pacHijack: boolean
  pacHijackHost: string
  forceChrome: boolean
  uptimeSeconds: number
  activeConns: number
  routes: RouteInfo[]
  dns: DnsEntry[]
}

export interface RouteForm {
  name: string
  gateway: string
  iface: string
  net: string
  pacUrl: string
  proxyUrl: string
  credential: string
}

export interface CredentialForm {
  name: string
  user: string
  password: string
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init)
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    try {
      const j = await res.json()
      if (j.error) msg = j.error
    } catch {
      /* ignore */
    }
    throw new Error(msg)
  }
  return res.json()
}

const post = (path: string, body: unknown) =>
  req(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

export const api = {
  state: () => req<StateInfo>('/api/state'),
  routes: () => req<RouteInfo[]>('/api/routes'),
  saveRoute: (r: RouteForm) => post('/api/routes', r),
  deleteRoute: (name: string) => req(`/api/routes/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  credentials: () => req<Credential[]>('/api/credentials'),
  saveCredential: (c: CredentialForm) => post('/api/credentials', c),
  deleteCredential: (name: string) => req(`/api/credentials/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  connections: (closed: boolean) => req<ConnInfo[]>(`/api/connections${closed ? '?closed=1' : ''}`),
  closeConnection: (id: number) => post(`/api/connections/${id}/close`, {}),
  forceRoute: (name: string) => post('/api/force-route', { name }),
  refreshPac: (name: string) => post('/api/pac/refresh', { name }),
  saveConfig: (form: {
    address: string
    systemProxy: boolean
    systemProxyExclude: string[]
    pacHijack: boolean
    pacHijackHost: string
    forceChrome: boolean
  }) => post('/api/config', form),
  systemProxy: () => req<SystemProxyState>('/api/system-proxy'),
}
