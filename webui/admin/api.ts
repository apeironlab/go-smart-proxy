import type { NetContext } from '../src/api'

export class AdminApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

export interface LoginMethod {
  id: string
  type: string
  label: string
  flow: 'form' | 'browser' | 'code'
}

export interface SessionInfo {
  authenticated: boolean
  methods: LoginMethod[]
  email?: string
  csrf?: string
  expires?: string
}

export interface OnlineDevice {
  email: string
  device: string
  addr: string
  serial: string
  since: string
  context?: NetContext
}

export interface AdminEvent {
  id: number
  time: string
  kind: string
  actor?: string
  subject?: string
  detail?: string
}

export interface Overview {
  now: string
  uptime: number
  counts: Record<'apps' | 'gateways' | 'devices' | 'users' | 'certs' | 'revokedCerts' | 'expiring' | 'pending' | 'localUsers' | 'revokedUsers', number>
  online: OnlineDevice[]
  recent: AdminEvent[]
}

export interface UserInfo {
  email: string
  certs: number
  revoked: boolean
  devices: number
  lastSeen: number
  local?: string
  lastCert?: number
}

export interface CertRecord {
  serial: string
  email: string
  device?: string
  method?: string
  issued: string
  expires: string
  revoked: boolean
  revokedBy?: string
}

export interface AdminDevice {
  device: string
  online: boolean
  addr?: string
  since?: string
  context?: { label?: string; vpn?: boolean }
  certs: CertRecord[]
}

export interface InviteResult {
  sent: number
  results: { email: string; ok: boolean; error?: string }[]
}

export interface LocalUser {
  username: string
  email: string
  groups: string[]
  created: string
}

export interface MethodRules {
  id: string
  type: string
  label: string
  disabled: boolean
  groups: string[]
  defaultGroups: string[]
}

export interface SmtpRules {
  addr: string
  user: string
  from: string
  tls: string
  auth: string
  hasPass: boolean
}

export interface AppDef {
  id: string
  name: string
  description?: string
  host: string
  kind: 'tcp' | 'http'
  gateway: string
  target: string
  everyone?: boolean
  emails?: string[]
  groups?: string[]
  setHeaders?: Record<string, string>
  disabled?: boolean
}

export interface GatewayCert {
  serial: string
  id: string
  issued: string
  expires: string
  revoked: boolean
}

export interface GatewayInfo {
  id: string
  online: boolean
  apps: number
  certs: GatewayCert[]
}

export interface GatewayIssued {
  id: string
  serial: string
  expires: string
  certPem: string
  keyPem: string
  caPem: string
}

export interface PolicyRule {
  id: string
  name: string
  mandatory?: boolean
  domains?: string[]
  nets?: string[]
  disabled?: boolean
}

export interface PolicyList {
  id: string
  name: string
  url: string
  format?: string
  mandatory?: boolean
  disabled?: boolean
}

export interface PolicyConfig {
  rules: PolicyRule[]
  lists: PolicyList[]
  allow: string[]
  refreshHours?: number
  requireLocalAuth?: boolean
}

export interface PolicyInfo {
  enabled: boolean
  readOnly?: boolean
  config: PolicyConfig
  lists: { id: string; entries: number; fetched: string; error?: string }[]
  counts: Record<string, number>
  recent: { time: string; email: string; host: string; source: string }[]
}

export interface Rules {
  allowedDomains: string[]
  certTtlHours: number
  methods: MethodRules[]
  smtp: SmtpRules
  admins: { groups: string[] | null; emails: string[] | null }
}

export interface RulesUpdate {
  allowedDomains: string[]
  certTtlHours: number
  methods: { id: string; disabled: boolean; groups: string[] }[]
  smtp: { addr: string; user: string; from: string; tls: string; auth: string; pass?: string }
}

let csrf = ''
let onAuthLost: () => void = () => {}

export const setCsrf = (v: string) => { csrf = v }
export const setAuthLostHandler = (fn: () => void) => { onAuthLost = fn }

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf
  const res = await fetch(path, {
    method, headers, credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    try {
      const err = ((await res.json()) as { error?: string }).error
      if (err) msg = err
    } catch {
      /* not JSON */
    }
    // The session ended (or never existed): back to the sign-in page. A wrong
    // password is also 401, but those calls are the sign-in itself.
    if (res.status === 401 && !path.includes('/login/')) onAuthLost()
    throw new AdminApiError(msg, res.status)
  }
  return res.json()
}

const q = (params: Record<string, string | number | undefined>) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const adminApi = {
  session: () => req<SessionInfo>('GET', '/admin/api/session'),
  login: (method: string, username: string, password: string) =>
    req<{ ok: boolean }>('POST', `/admin/api/login/${encodeURIComponent(method)}`, { username, password }),
  loginStart: (method: string) => req<{ authUrl: string }>('POST', `/admin/api/login/${encodeURIComponent(method)}/start`),
  logout: () => req<{ ok: boolean }>('POST', '/admin/api/logout'),

  overview: () => req<Overview>('GET', '/admin/api/overview'),
  users: () => req<UserInfo[]>('GET', '/admin/api/users'),
  certs: (email: string) => req<CertRecord[]>('GET', `/admin/api/certs${q({ email })}`),
  revoke: (target: { email?: string; serial?: string }) =>
    req<{ ok: boolean; disconnected: number }>('POST', '/admin/api/revoke', target),
  unrevoke: (target: { email?: string; serial?: string }) => req<{ ok: boolean }>('POST', '/admin/api/unrevoke', target),
  devices: (email: string) => req<AdminDevice[]>('GET', `/admin/api/devices${q({ email })}`),
  revokeDevice: (email: string, device: string, forget = false) =>
    req<{ ok: boolean; revoked: number; disconnected: number }>('POST', '/admin/api/revoke-device', { email, device, forget }),
  invite: (emails: string[]) => req<InviteResult>('POST', '/admin/api/invite', { emails }),
  kick: (email: string) => req<{ ok: boolean; disconnected: number }>('POST', '/admin/api/kick', { email }),

  localUsers: () => req<{ enabled: boolean; users: LocalUser[] }>('GET', '/admin/api/local-users'),
  addLocalUser: (u: { username: string; password: string; email: string; groups: string[] }) =>
    req<{ ok: boolean }>('POST', '/admin/api/local-users', u),
  editLocalUser: (name: string, u: { password?: string; email: string; groups: string[] }) =>
    req<{ ok: boolean }>('PUT', `/admin/api/local-users/${encodeURIComponent(name)}`, u),
  deleteLocalUser: (name: string) => req<{ ok: boolean }>('DELETE', `/admin/api/local-users/${encodeURIComponent(name)}`),

  rules: () => req<Rules>('GET', '/admin/api/rules'),
  saveRules: (r: RulesUpdate) => req<Rules>('PUT', '/admin/api/rules', r),
  apps: () => req<{ enabled: boolean; readOnly?: boolean; apps: AppDef[] }>('GET', '/admin/api/apps'),
  saveApps: (apps: AppDef[]) => req<{ enabled: boolean; readOnly?: boolean; apps: AppDef[] }>('PUT', '/admin/api/apps', { apps }),
  gateways: () => req<GatewayInfo[]>('GET', '/admin/api/gateways'),
  issueGateway: (id: string) => req<GatewayIssued>('POST', '/admin/api/gateways', { id }),
  revokeGateway: (id: string) => req<{ ok: boolean; revoked: number }>('POST', `/admin/api/gateways/${encodeURIComponent(id)}/revoke`),
  policy: () => req<PolicyInfo>('GET', '/admin/api/policy'),
  savePolicy: (config: PolicyConfig) => req<PolicyInfo>('PUT', '/admin/api/policy', { config }),
  refreshPolicy: () => req<PolicyInfo>('POST', '/admin/api/policy/refresh'),
  events: (f: { kind?: string; q?: string; before?: number; limit?: number }) =>
    req<AdminEvent[]>('GET', `/admin/api/events${q(f)}`),
}
