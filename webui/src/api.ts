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
  exitVpn?: string
  exitLabel?: string
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
  interfaces?: IfaceProxy[] | null
  transparent?: TransparentStatus
}

export interface TransparentStatus {
  configured: string[]
  interfaces: string[]
  loaded: boolean
  error: string
  hint: string
}

export interface IfaceProxy {
  service: string
  iface: string
  primary: boolean
  dynamic: boolean
  excluded: boolean
  httpEnabled: boolean
  httpProxy: string
  httpPort: number
  httpsEnabled: boolean
  httpsProxy: string
  httpsPort: number
  pacEnabled: boolean
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
  transparentRoute: string[]
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
  exitVpn: string
  exitLabel: string
  hops: Hop[]
  rulesOnly: boolean
}

export interface CredentialForm {
  name: string
  user: string
  password: string
}

// One way a relay lets users sign in. Flow: "code" (a code sent by e-mail),
// "form" (user name and password typed here) or "browser" (the provider's page).
export interface EnrollMethod {
  id: string
  type: string
  label: string
  flow: 'code' | 'form' | 'browser'
}

export interface EnrollRequest {
  name: string
  address: string
  email: string
  caPem: string
  acceptFingerprint: string
  method: string
}

export interface EnrollStatus {
  pending: boolean
  name?: string
  phase?: string // "code" or "browser"
  authUrl?: string
  // The code to type on the relay's confirmation page after signing in.
  userCode?: string
  email?: string
  address?: string
  expiresAt?: string
  // How the last enrollment ended, for a couple of minutes.
  result?: { name: string; error: string }
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
    // The interface is protected by an access token: ask for it.
    if (res.status === 401 && !path.startsWith('/api/auth/')) window.dispatchEvent(new Event('gsp-auth-required'))
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

// Query string naming the relay a call is about.
const rq = (relay?: string) => (relay ? `?relay=${encodeURIComponent(relay)}` : '')

const post = <T = unknown>(path: string, body: unknown) =>
  req<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

export interface AppEntry {
  relay: string
  id: string
  name: string
  description: string
  host: string
  kind: 'tcp' | 'http'
  online: boolean
  url: string
}

export interface BlockList {
  name: string
  url: string
  format: string
  enabled: boolean
}

export interface BlockingConfig {
  enabled: boolean
  presets: string[]
  lists: BlockList[]
  block: string[]
  allow: string[]
  relayOff: string[]
  refreshHours: number
}

export interface BlockingInfo {
  config: BlockingConfig
  presets: { id: string; name: string; description: string; url: string; format: string; enabled: boolean }[]
  lists: { key: string; name: string; entries: number; fetched: string; error: string }[]
  relays: { relay: string; mandatory: number; recommended: { id: string; name: string; enabled: boolean }[] }[]
  updating: boolean
}

export interface BlockingStats {
  total: number
  bySource: Record<string, number>
  top: { host: string; count: number }[]
  recent: { time: string; host: string; source: string; client: string }[]
}

export interface BlockingTest {
  host: string
  blocked: boolean
  mandatory: boolean
  source?: string
  rule?: string
}

export interface SecurityInfo {
  recoveryEnabled: boolean
  recoveryCreated?: string
  recovered: boolean
  keychain: boolean
}

export interface AuthInfo {
  required: boolean
  imposed: boolean
  signedIn: boolean
  tokenFile?: string
}

export const api = {
  authInfo: () => req<AuthInfo>('/api/auth/info'),
  login: (token: string) => post('/api/auth/login', { token }),
  logout: () => post('/api/auth/logout', {}),
  setAuthEnabled: (enabled: boolean) => req('/api/auth/config', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }),
  }),
  rotateToken: () => post('/api/auth/rotate', {}),
  authToken: () => req<{ token: string }>('/api/auth/token'),
  security: () => req<SecurityInfo>('/api/security'),
  changePassword: (oldPassword: string, newPassword: string) => post('/api/security/password', { old: oldPassword, new: newPassword }),
  createRecoveryKey: (password: string) => post<{ key: string }>('/api/security/recovery', { password }),
  removeRecoveryKey: (password: string) => post('/api/security/recovery/remove', { password }),
  blocking: () => req<BlockingInfo>('/api/blocking'),
  saveBlocking: (c: BlockingConfig) => req<BlockingInfo>('/api/blocking', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(c),
  }),
  refreshBlocking: () => post('/api/blocking/refresh', {}),
  blockingStats: () => req<BlockingStats>('/api/blocking/stats'),
  resetBlockingStats: () => post('/api/blocking/stats/reset', {}),
  testBlocking: (host: string) => req<BlockingTest>(`/api/blocking/test?host=${encodeURIComponent(host)}`),
  apps: () => req<AppEntry[]>('/api/apps'),
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
    transparentRoute?: string[]
    forceChrome: boolean
    allowRemoteClients?: boolean
  }) => post('/api/config', form),
  finishOnboarding: () => post('/api/onboarding', {}),
  // Every relay call can name the relay it is about; without a name the first one is used.
  relay: (relay?: string) => req<RelayStatus>('/api/relay' + rq(relay)),
  // All relays at once.
  relays: () => req<RelayStatus[]>('/api/relays'),
  relayConfig: (relay?: string) => req<RelayConfigInfo>('/api/relay/config' + rq(relay)),
  relayConfigs: () => req<RelayConfigInfo[]>('/api/relays/config'),
  // An unknown name adds a relay.
  saveRelayConfig: (form: RelayConfigForm, relay?: string) =>
    post<RelayConfigInfo>('/api/relay/config' + rq(relay), { ...form, name: relay ?? '' }),
  deleteRelay: (relay: string) => req('/api/relay/config' + rq(relay), { method: 'DELETE' }),
  // The first request of an enrollment. The relay either sends an e-mail code
  // ("code_sent") or, when it offers several ways to sign in, answers 401 with
  // the list ("auth_required"). method "email" asks for the code by name.
  relayEnroll: (address: string, email: string, caPem: string, acceptFingerprint = '', name = '', method = '') =>
    post<{ status: 'code_sent' | 'auth_required'; methods?: EnrollMethod[] }>('/api/relay/enroll', { name, address, email, caPem, acceptFingerprint, method }),
  relayEnrollStatus: () => req<EnrollStatus>('/api/relay/enroll'),
  // User name and password typed in the proxy (methods password and ldap).
  relayEnrollLogin: (b: EnrollRequest & { username: string; password: string }) => post('/api/relay/enroll/login', b),
  // Sign-in on the provider's page (OpenID Connect, SAML): returns the page to open.
  relayEnrollStart: (b: EnrollRequest) => post<{ authUrl: string; userCode: string }>('/api/relay/enroll/start', b),
  relayEnrollCancel: () => req('/api/relay/enroll', { method: 'DELETE' }),
  relayConfirm: (code: string) => post('/api/relay/enroll/confirm', { code }),
  relayRequest: (email: string, relay?: string) => post('/api/relay/contacts' + rq(relay), { email }),
  // Measures the round trip to the relay (empty email) or to a contact's device.
  relayPing: (email = '', device = '', relay?: string) => post<PingResult>('/api/relay/ping' + rq(relay), { email, device }),
  relayRespond: (email: string, accept: boolean, relay?: string) => post('/api/relay/contacts/respond' + rq(relay), { email, accept }),
  relayRemove: (email: string, relay?: string) => post('/api/relay/contacts/remove' + rq(relay), { email }),
  relayDecide: (id: number, d: { allow: boolean; always?: boolean; anyPort?: boolean }, relay?: string) =>
    post(`/api/relay/approvals/${id}` + rq(relay), d),
  relayDeleteRule: (id: number, relay?: string) => req(`/api/relay/rules/${id}` + rq(relay), { method: 'DELETE' }),
  relaySetDevice: (device: string, relay?: string) => post('/api/relay/device' + rq(relay), { device }),
  rules: () => req<RoutingRule[]>('/api/rules'),
  saveRules: (r: RoutingRule[]) => post('/api/rules', r),
  testRule: (host: string) => req<RuleTest>(`/api/rules/test?host=${encodeURIComponent(host)}`),
  systemProxy: () => req<SystemProxyState>('/api/system-proxy'),
}

export interface RelayContact {
  email: string
  online: boolean
  devices?: string[]
  // Unix seconds of the last time the contact was online (offline contacts only).
  lastSeen?: number
  // Context shared by each online device, by device code.
  context?: Record<string, NetContext>
}

export interface PingResult {
  ok: boolean
  rttMs?: number
  error?: string
}

export interface RelayApproval {
  id: number
  from: string
  fromDevice?: string
  host: string
  port: number
  time: string
}

// What a device chooses to tell its contacts about its network: a label picked
// by its user and whether a VPN is active. Nothing else.
export interface NetContext {
  label?: string
  vpn?: boolean
}

export interface RelayDeviceInfo {
  id: string
  online: boolean
  context?: NetContext
}

export interface RelayRule {
  id: number
  from: string
  fromDevice?: string
  host: string
  port: number
}

export interface RelayStatus {
  certExpires?: string
  deviceBound?: boolean
  name: string
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

// A name for a network, recognised by local conditions (all that are set must hold).
export interface NetworkLabelRule {
  label: string
  vpn: string
  ifaceUp: string
  iface: string
  net: string
  gateway: string
}

export interface SharedNow {
  sharing: boolean
  label: string
  vpn: boolean
  rule: number // index of the matching entry, -1 = default label
}

export interface RelayConfigInfo {
  name: string
  address: string
  route: string
  allowLocal: boolean
  device: string
  enrollUrl?: string
  hasCertificate: boolean
  hasCA: boolean
  networkLabel: string
  networkLabels: NetworkLabelRule[]
  shareContext: boolean
  sharedNow: SharedNow
}

export interface RelayConfigForm {
  address: string
  route: string
  allowLocal: boolean
  networkLabel?: string
  networkLabels?: NetworkLabelRule[]
  shareContext?: boolean
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
  // Conditions on the exit of the route's relay hop.
  exitVpn?: string
  exitLabel?: string
}

export interface RuleTest {
  route?: string
  rule: string
  ip: string
}
