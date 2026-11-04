export interface Hop {
  proxyUrl?: string
  pacUrl?: string
  dynamic?: boolean
  credential?: string
  rulesOnly?: boolean
}

export interface RouteInfo {
  name: string
  gateway: string
  iface: string
  net: string
  ifaceUp?: string
  vpn?: string
  chain?: string[] | null
  hops?: Hop[] | null
  rulesOnly: boolean
  applicable: boolean
  whyNot: string
  pacStatus: string
  pacError: string
}

export interface Credential {
  name: string
  user: string
  hasPassword: boolean
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

export interface IfaceStatus {
  name: string
  up: boolean
  addrs: string[]
  vpnLike: boolean
  routed: boolean
  default: boolean
  active: boolean
  vpn: boolean
}

export interface VpnState {
  active: boolean
  interfaces: string[]
  defaultIface: string
  all: IfaceStatus[]
}

export interface StateInfo {
  address: string
  socksAddress: string
  onboarding: boolean
  hosts: Record<string, string>
  iface: string
  gateway: string
  network: string
  forceRoute: string
  systemProxy: boolean
  systemProxyExclude: string[]
  forceChrome: boolean
  allowRemoteClients: boolean
  uptimeSeconds: number
  activeConns: number
  routes: RouteInfo[]
  dns: DnsEntry[]
  vpn: VpnState
}

export interface RouteForm {
  name: string
  gateway: string
  iface: string
  net: string
  ifaceUp: string
  vpn: string
  hops: Hop[]
  rulesOnly: boolean
}

export interface CredentialForm {
  name: string
  user: string
  password: string
}

export interface CertificatePrompt {
  subject: string
  issuer: string
  fingerprint: string
  caSubject?: string
  caFingerprint?: string
}

export class ApiError extends Error {
  payload?: unknown
  constructor(message: string, payload?: unknown) {
    super(message)
    this.payload = payload
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init)
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    let payload: unknown = undefined
    try {
      payload = await res.json()
      const err = (payload as { error?: string })?.error
      if (err) msg = err
    } catch {
      /* ignore */
    }
    throw new ApiError(msg, payload)
  }
  return res.json()
}

const post = <T = unknown>(path: string, body: unknown) =>
  req<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

export const api = {
  state: () => req<StateInfo>('/api/state'),
  routes: () => req<RouteInfo[]>('/api/routes'),
  reorderRoutes: (names: string[]) => post('/api/routes/order', { names }),
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
    socksAddress: string
    hosts: Record<string, string>
    systemProxy: boolean
    systemProxyExclude: string[]
    forceChrome: boolean
    allowRemoteClients?: boolean
  }) => post('/api/config', form),
  finishOnboarding: () => post('/api/onboarding', {}),
  relay: () => req<RelayStatus>('/api/relay'),
  relayConfig: () => req<RelayConfigInfo>('/api/relay/config'),
  saveRelayConfig: (form: RelayConfigForm) => post<RelayConfigInfo>('/api/relay/config', form),
  relayEnroll: (address: string, email: string, caPem: string, acceptFingerprint = '') =>
    post('/api/relay/enroll', { address, email, caPem, acceptFingerprint }),
  relayEnrollStatus: () => req<{ pending: boolean; email?: string; address?: string; expiresAt?: string }>('/api/relay/enroll'),
  relayConfirm: (code: string) => post('/api/relay/enroll/confirm', { code }),
  relayRequest: (email: string) => post('/api/relay/contacts', { email }),
  relayRespond: (email: string, accept: boolean) => post('/api/relay/contacts/respond', { email, accept }),
  relayRemove: (email: string) => post('/api/relay/contacts/remove', { email }),
  relayDecide: (id: number, d: { allow: boolean; always?: boolean; anyPort?: boolean }) =>
    post(`/api/relay/approvals/${id}`, d),
  relayDeleteRule: (id: number) => req(`/api/relay/rules/${id}`, { method: 'DELETE' }),
  relaySetDevice: (device: string) => post('/api/relay/device', { device }),
  rules: () => req<RoutingRule[]>('/api/rules'),
  saveRules: (r: RoutingRule[]) => post('/api/rules', r),
  testRule: (host: string) => req<RuleTest>(`/api/rules/test?host=${encodeURIComponent(host)}`),
  systemProxy: () => req<SystemProxyState>('/api/system-proxy'),
}

export interface RelayContact {
  email: string
  online: boolean
  devices?: string[]
}

export interface RelayApproval {
  id: number
  from: string
  fromDevice?: string
  host: string
  port: number
  time: string
}

export interface RelayDeviceInfo {
  id: string
  online: boolean
}

export interface RelayRule {
  id: number
  from: string
  fromDevice?: string
  host: string
  port: number
}

export interface RelayStatus {
  enabled: boolean
  connected: boolean
  address: string
  route: string
  email: string
  device: string
  enrollUrl?: string
  error?: string
  notice?: string
  contacts: RelayContact[]
  myDevices: RelayDeviceInfo[]
  incoming: string[]
  outgoing: string[]
  approvals: RelayApproval[]
  rules: RelayRule[]
}

export interface RelayConfigInfo {
  address: string
  route: string
  allowLocal: boolean
  device: string
  enrollUrl?: string
  hasCertificate: boolean
  hasCA: boolean
}

export interface RelayConfigForm {
  address: string
  route: string
  allowLocal: boolean
  certPem: string
  keyPem: string
  caPem: string
  clearCertificate?: boolean
}

export interface RoutingRule {
  name: string
  domains: string[]
  hosts: string[]
  networks: string[]
  route: string
}

export interface RuleTest {
  route?: string
  rule: string
  ip: string
}
