import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  ActionIcon, Alert, Autocomplete, Badge, Button, Card, Checkbox, Code, Divider, Group, Modal, Paper, Select, SimpleGrid, Stack, Switch, Table,
  TagsInput, Text, Textarea, TextInput, Tabs, Tooltip, Accordion,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import {
  IconAlertTriangle, IconArrowDown, IconArrowUp, IconClock, IconNetwork, IconPencil, IconPlugConnected, IconPlus,
  IconRefresh, IconRoute, IconRouteAltRight, IconServer, IconSettings, IconTrash,
} from '@tabler/icons-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { api } from '../api'
import type { Credential, Hop, RelayConfigInfo, RelayStatus, RouteInfo, StateInfo, SystemProxyState } from '../api'
import { PageHeader, Section, StatCard } from '../components/ui'

const pacColors: Record<string, string> = {
  none: 'gray',
  loaded: 'green',
  loading: 'yellow',
  error: 'red',
}

function fmtUptime(seconds: number) {
  const m = Math.floor(seconds / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h ${m % 60}m`
  return `${Math.floor(h / 24)}d ${h % 24}h`
}

const isLoopback = (addr: string) => {
  const host = addr.trim().replace(/:\d+$/, '').replace(/^\[|\]$/g, '')
  return !addr.trim() || host === 'localhost' || host === '::1' || /^127\./.test(host)
}

// Quick client-side check, mirrored by the server: host:port with a valid port.
const addressProblem = (addr: string, optional: boolean): string | undefined => {
  const v = addr.trim()
  if (!v) return optional ? undefined : 'required'
  const m = v.match(/^(\[[^\]]+\]|[^:\s]*):(\d+)$/)
  if (!m) return 'host:port'
  const port = Number(m[2])
  return port >= 1 && port <= 65535 ? undefined : 'port 1-65535'
}

function chainText(r: RouteInfo, t: TFunction) {
  if (r.hops?.length) {
    return r.hops
      .map((h, i) => {
        const text = h.dynamic
          ? t('dynamic')
          : h.pacUrl
            ? `pac ${h.pacUrl}`
            : (r.chain?.[i] ?? h.proxyUrl ?? '')
        return h.rulesOnly ? t('{{text}} (rules)', { text }) : text
      })
      .join(' → ')
  }
  return r.chain?.length ? r.chain.join(' → ') : '-'
}

type HopKind = 'proxy' | 'pac' | 'dynamic'
type HopForm = Hop & { kind?: HopKind }

const hopKind = (h: HopForm): HopKind =>
  h.kind ?? (h.dynamic ? 'dynamic' : h.pacUrl ? 'pac' : 'proxy')

export default function ConfigPage() {
  const { t } = useTranslation()
  const [state, setState] = useState<StateInfo | null>(null)
  const [relaySt, setRelaySt] = useState<RelayStatus | null>(null)
  const [creds, setCreds] = useState<Credential[]>([])
  const [error, setError] = useState<string | null>(null)
  const [address, setAddress] = useState('')
  const [socksAddress, setSocksAddress] = useState('')
  const [hosts, setHosts] = useState<{ host: string; ip: string }[]>([])
  const [relayCfg, setRelayCfg] = useState<RelayConfigInfo | null>(null)
  const [relayAddress, setRelayAddress] = useState('')
  const [relayRoute, setRelayRoute] = useState('')
  const [relayAllowLocal, setRelayAllowLocal] = useState(false)
  const [relayCert, setRelayCert] = useState('')
  const [relayKey, setRelayKey] = useState('')
  const [relayCA, setRelayCA] = useState('')
  const [sysProxy, setSysProxy] = useState(false)
  const [exclude, setExclude] = useState<string[]>([])
  const [forceChrome, setForceChrome] = useState(false)
  const [allowRemote, setAllowRemote] = useState(false)
  const [tab, setTab] = useState<string>(() => {
    try { return sessionStorage.getItem('gsp.configTab') || 'network' } catch { return 'network' }
  })
  const changeTab = (v: string) => {
    setTab(v)
    try { sessionStorage.setItem('gsp.configTab', v) } catch { /* ignore */ }
  }
  const addressError = address ? addressProblem(address, false) : undefined
  const socksError = addressProblem(socksAddress, true)
  const [sysProxyState, setSysProxyState] = useState<SystemProxyState | null>(null)
  const [forceRoute, setForceRoute] = useState<string>('')
  const [configLoaded, setConfigLoaded] = useState(false)
  const [opened, { open, close }] = useDisclosure(false)
  const [editing, setEditing] = useState<RouteInfo | null>(null)
  const [form, setForm] = useState({
    name: '', gateway: '', iface: '', net: '', ifaceUp: '', vpn: '',
    hops: [] as HopForm[], rulesOnly: false,
  })
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    api.state().then((s) => {
      setState(s)
      if (!configLoaded) {
        setAddress(s.address)
        setSocksAddress(s.socksAddress ?? '')
        setHosts(Object.entries(s.hosts ?? {}).map(([host, ip]) => ({ host, ip })))
        setSysProxy(s.systemProxy)
        setExclude(s.systemProxyExclude ?? [])
        setForceChrome(s.forceChrome)
        setAllowRemote(s.allowRemoteClients)
        setForceRoute(s.forceRoute || '')
        setConfigLoaded(true)
      }
    }).catch((e) => setError(String(e)))
    api.credentials().then(setCreds).catch(() => {})
    api.systemProxy().then(setSysProxyState).catch(() => {})
    api.relay().then(setRelaySt).catch(() => {})
    api.relayConfig().then((rc) => {
      setRelayCfg(rc)
      if (!configLoaded) {
        setRelayAddress(rc.address)
        setRelayRoute(rc.route)
        setRelayAllowLocal(rc.allowLocal)
      }
    }).catch(() => {})
  }, [configLoaded])

  useEffect(() => {
    load()
    const timer = setInterval(load, 5000)
    return () => clearInterval(timer)
  }, [load])

  const hostsObject = () =>
    Object.fromEntries(
      hosts
        .filter((h) => h.host.trim() && h.ip.trim())
        .map((h) => [h.host.trim().toLowerCase(), h.ip.trim()]),
    )

  const setHostRow = (i: number, patch: Partial<{ host: string; ip: string }>) =>
    setHosts(hosts.map((h, j) => (j === i ? { ...h, ...patch } : h)))

  const saveConfig = async () => {
    try {
      await api.saveConfig({
        address,
        socksAddress,
        hosts: hostsObject(),
        systemProxy: sysProxy,
        systemProxyExclude: exclude,
        forceChrome,
      })
      load()
    } catch (e) {
      setError(String(e))
    }
  }

  const saveRelay = async (clearCertificate = false) => {
    try {
      setError(null)
      const info = await api.saveRelayConfig({
        address: relayAddress.trim(),
        route: relayRoute,
        allowLocal: relayAllowLocal,
        certPem: relayCert,
        keyPem: relayKey,
        caPem: relayCA,
        clearCertificate,
      })
      setRelayCfg(info)
      setRelayCert('')
      setRelayKey('')
      setRelayCA('')
      load()
    } catch (e) {
      setError(String(e))
    }
  }

  const applyForceRoute = async (name: string | null) => {
    setForceRoute(name ?? '')
    try {
      await api.forceRoute(name ?? '')
      load()
    } catch (e) {
      setError(String(e))
    }
  }

  const openNew = () => {
    setEditing(null)
    setForm({ name: '', gateway: '', iface: '', net: '', ifaceUp: '', vpn: '', hops: [], rulesOnly: false })
    open()
  }

  const openEdit = (r: RouteInfo) => {
    setEditing(r)
    setForm({
      name: r.name, gateway: r.gateway, iface: r.iface, net: r.net,
      ifaceUp: r.ifaceUp ?? '', vpn: r.vpn ?? '',
      hops: (r.hops ?? []).map((h) => ({
        proxyUrl: h.proxyUrl ?? '',
        pacUrl: h.pacUrl ?? '',
        dynamic: h.dynamic ?? false,
        credential: h.credential ?? '',
        rulesOnly: h.rulesOnly ?? false,
        kind: hopKind(h),
      })),
      rulesOnly: r.rulesOnly ?? false,
    })
    open()
  }

  const setHop = (i: number, patch: Partial<HopForm>) =>
    setForm({ ...form, hops: form.hops.map((h, j) => (j === i ? { ...h, ...patch } : h)) })
  const setHopKind = (i: number, kind: HopKind) => {
    const hop = form.hops[i]
    if (kind === 'pac') {
      // A PAC is not a proxy: it must be the only hop of the chain. Keep the
      // kind explicit even while the URL is still empty, otherwise the select
      // would immediately fall back to "proxy".
      setForm({
        ...form,
        hops: [{
          proxyUrl: '', pacUrl: hop.pacUrl ?? '', dynamic: false, credential: hop.credential,
          rulesOnly: hop.rulesOnly, kind: 'pac',
        }],
      })
    } else if (kind === 'dynamic') {
      // A dynamic hop is terminal: keep the prefix and drop what came after.
      setForm({
        ...form,
        hops: [
          ...form.hops.slice(0, i),
          { proxyUrl: '', pacUrl: '', dynamic: true, credential: '', rulesOnly: hop.rulesOnly, kind: 'dynamic' },
        ],
      })
    } else {
      setHop(i, { pacUrl: '', dynamic: false, kind: 'proxy' })
    }
  }
  const moveHop = (i: number, d: number) => {
    const hops = [...form.hops]
    ;[hops[i], hops[i + d]] = [hops[i + d], hops[i]]
    setForm({ ...form, hops })
  }

  const save = async () => {
    setBusy(true)
    try {
      const hops = form.hops.map((h) => {
        const copy = { ...h }
        delete copy.kind
        return copy
      })
      await api.saveRoute({ ...form, hops })
      close()
      load()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (name: string) => {
    if (!window.confirm(t('Delete route "{{name}}"?', { name }))) return
    try {
      await api.deleteRoute(name)
      load()
    } catch (e) {
      setError(String(e))
    }
  }

  const routes = state?.routes ?? []
  // Rules-only routes are selected exclusively by destination rules: they
  // cannot be forced manually, so they are not offered by the selectors.
  const selectableRoutes = routes.filter((r) => !r.rulesOnly)
  const credOptions = creds.map((c) => ({ value: c.name, label: c.name }))
  const configRouteNames = routes.filter((r) => r.name !== 'Direct').map((r) => r.name)
  const routePos = (name: string) => configRouteNames.indexOf(name)

  const moveRoute = async (name: string, delta: number) => {
    const pos = routePos(name)
    const target = pos + delta
    if (pos < 0 || target < 0 || target >= configRouteNames.length) return
    const names = [...configRouteNames]
    ;[names[pos], names[target]] = [names[target], names[pos]]
    try {
      await api.reorderRoutes(names)
      load()
    } catch (e) {
      setError(String(e))
    }
  }

  // Suggestions for the hop editor: relay contacts/devices plus every hop
  // already used by another route.
  const hopSuggestions = useMemo(() => {
    const seen = new Set<string>()
    const out: string[] = []
    const add = (v: string) => {
      if (v && !seen.has(v)) {
        seen.add(v)
        out.push(v)
      }
    }
    for (const r of state?.routes ?? []) {
      for (const h of r.hops ?? []) {
        if (h.proxyUrl) add(h.proxyUrl)
      }
    }
    for (const c of relaySt?.contacts ?? []) {
      add(`relay://${c.email}`)
      for (const d of c.devices ?? []) add(`relay://${c.email}/${d}`)
    }
    if (relaySt?.email) {
      for (const d of relaySt.myDevices ?? []) add(`relay://${relaySt.email}/${d.id}`)
    }
    return out
  }, [state, relaySt])

  return (
    <>
      <PageHeader
        icon={IconSettings}
        title={t('Configuration')}
        description={t('Listeners, system proxy, fixed hosts, routes and relay connection.')}
      />
      {error && <Alert color="red" mb="md" withCloseButton onClose={() => setError(null)}>{t('Error: {{error}}', { error })}</Alert>}

      <Tabs value={tab} onChange={(v) => changeTab(v ?? 'network')} keepMounted={false}>
        <Tabs.List mb="lg" style={{ flexWrap: 'nowrap', overflowX: 'auto' }}>
          <Tabs.Tab value="network" leftSection={<IconNetwork size={16} />}>{t('Network')}</Tabs.Tab>
          <Tabs.Tab value="routes" leftSection={<IconRoute size={16} />}>{t('Routes')}</Tabs.Tab>
          <Tabs.Tab value="hosts" leftSection={<IconServer size={16} />}>{t('Hosts and DNS')}</Tabs.Tab>
          <Tabs.Tab value="relay" leftSection={<IconRouteAltRight size={16} />}>{t('Relay')}</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="network">
          <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }} mb="lg">
            <StatCard label={t('Current interface')} value={state?.iface || '-'} icon={IconNetwork} />
            <StatCard label={t('Gateway')} value={state?.gateway || '-'} icon={IconRoute} color="cyan" />
            <StatCard label={t('Network')} value={state?.network || '-'} icon={IconServer} color="grape" />
            <StatCard label={t('Uptime')} value={state ? fmtUptime(state.uptimeSeconds) : '-'} icon={IconClock} color="teal" />
            <StatCard label={t('Active connections')} value={String(state?.activeConns ?? 0)} icon={IconPlugConnected} color="orange" />
          </SimpleGrid>

          <Section
            title={t('Listeners')}
            description={t('Where the proxy accepts connections from your applications. The listener restarts automatically.')}
          >
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label={t('Listen address')}
                description={t('HTTP proxy and web UI')}
                placeholder="127.0.0.1:3128"
                value={address}
                error={addressError}
                onChange={(e) => setAddress(e.currentTarget.value)}
              />
              <TextInput
                label={t('SOCKS5')}
                description={t('Empty = disabled')}
                placeholder="127.0.0.1:1080"
                value={socksAddress}
                error={socksError}
                onChange={(e) => setSocksAddress(e.currentTarget.value)}
              />
            </SimpleGrid>
            <Group justify="flex-end" mt="md">
              <Button onClick={saveConfig} disabled={!address || !!addressError || !!socksError}>{t('Save')}</Button>
            </Group>
            <Divider my="md" />
            <Switch
              color="red"
              label={t('Allow other computers to use the proxy')}
              description={t('Off by default. The proxy has no client authentication and uses your upstream credentials: enable it only on a trusted network, and only if you need to listen on a non-loopback address')}
              checked={allowRemote}
              onChange={(e) => {
                const v = e.currentTarget.checked
                setAllowRemote(v)
                api.saveConfig({ address, socksAddress, hosts: hostsObject(), systemProxy: sysProxy, systemProxyExclude: exclude, forceChrome, allowRemoteClients: v })
                  .then(load)
                  .catch((err) => { setAllowRemote(!v); setError(String(err)) })
              }}
            />
            {(!isLoopback(address) || !isLoopback(socksAddress)) && (
              <Alert color="orange" mt="md" icon={<IconAlertTriangle size={18} />} title={t('Non-loopback address')}>
                {t('This address is reachable from other machines. Without "Allow other computers to use the proxy" the API refuses to save it, and connections from other computers are dropped.')}
              </Alert>
            )}
          </Section>

          <Section
            title={t('Route selection')}
            description={t('Empty = automatic. Destination rules are only evaluated in Auto.')}
          >
            <Select
              label={t('Forced route')}
              maw={360}
              clearable
              placeholder={t('Auto')}
              data={selectableRoutes.map((r) => ({ value: r.name, label: r.name }))}
              value={forceRoute || null}
              onChange={(v) => applyForceRoute(v)}
            />
          </Section>

          <Section
            title={t('Network and VPN detection')}
            description={t('What the proxy sees right now. In Auto mode the first route whose conditions match is used, so these are the facts the conditions are checked against.')}
            right={
              <Badge size="lg" variant="light" color={state?.vpn?.active ? 'grape' : 'gray'} tt="none">
                {state?.vpn?.active ? t('VPN connected: {{names}}', { names: state.vpn.interfaces.join(', ') }) : t('No VPN detected')}
              </Badge>
            }
          >
            <Table.ScrollContainer minWidth={560}>
              <Table verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('Interface')}</Table.Th>
                    <Table.Th>{t('Addresses')}</Table.Th>
                    <Table.Th>{t('State')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {(state?.vpn?.all ?? []).filter((i) => i.up).map((i) => (
                    <Table.Tr key={i.name} style={{ opacity: i.active ? 1 : 0.55 }}>
                      <Table.Td><Text fw={600} size="sm">{i.name}</Text></Table.Td>
                      <Table.Td><Text size="xs" c="dimmed" truncate="end" maw={320}>{(i.addrs ?? []).join(', ') || '-'}</Text></Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          {i.default && <Badge size="xs" color="blue" variant="light" tt="none">{t('default route')}</Badge>}
                          {i.vpn && <Badge size="xs" color="grape" variant="light" tt="none">VPN</Badge>}
                          {!i.vpn && i.vpnLike && <Badge size="xs" color="gray" variant="outline" tt="none">{t('tunnel, not in use')}</Badge>}
                          {i.active && !i.default && !i.vpn && <Badge size="xs" color="teal" variant="light" tt="none">{t('in use')}</Badge>}
                          {!i.active && <Badge size="xs" color="gray" variant="light" tt="none">{t('inactive')}</Badge>}
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
            <Text size="xs" c="dimmed" mt="sm">
              {t('An interface counts as in use only when it is up, has an IPv4 address and carries routes: tunnels left behind by a disconnected VPN client are ignored.')}
            </Text>
          </Section>

          <Section
            title={t('System proxy')}
            description={t('Keep the operating system pointed at this proxy, even when a VPN client rewrites it.')}
          >
            <Switch
              label={t('Reset system proxy on network change')}
              description={t('With Pulse connected it only rewrites the runtime state of the Pulse service (via scutil, no conflict or reconnections); without VPN it uses networksetup')}
              checked={sysProxy}
              onChange={(e) => {
                const v = e.currentTarget.checked
                setSysProxy(v)
                api.saveConfig({ address, socksAddress, hosts: hostsObject(), systemProxy: v, systemProxyExclude: exclude, forceChrome })
                  .then(load)
                  .catch((err) => setError(String(err)))
              }}
            />
            <TagsInput
              mt="md"
              label={t('System proxy exclusions')}
              description={t('Interfaces or service names to leave alone (e.g. utun4, VPN): avoids conflicts with the VPN client that keeps reconnecting')}
              placeholder="utun4"
              value={exclude}
              onChange={(v) => {
                setExclude(v)
                api.saveConfig({ address, socksAddress, hosts: hostsObject(), systemProxy: sysProxy, systemProxyExclude: v, forceChrome })
                  .then(load)
                  .catch((err) => setError(String(err)))
              }}
            />
        {sysProxyState && (
          <>
            <Divider my="md" />
            <Group gap="xs" mt="sm">
              <Text size="sm" fw={600}>{t('Effective system proxy (as seen by Chrome):')}</Text>
              <Badge
                color={sysProxyState.httpEnabled && sysProxyState.httpProxy ? 'green' : 'red'}
                variant="light"
              >
                HTTP: {sysProxyState.httpEnabled ? `${sysProxyState.httpProxy}:${sysProxyState.httpPort}` : t('disabled')}
              </Badge>
              <Badge
                color={sysProxyState.httpsEnabled && sysProxyState.httpsProxy ? 'green' : 'red'}
                variant="light"
              >
                HTTPS: {sysProxyState.httpsEnabled ? `${sysProxyState.httpsProxy}:${sysProxyState.httpsPort}` : t('disabled')}
              </Badge>
              <Badge color={sysProxyState.pacEnabled ? 'red' : 'gray'} variant="light">
                PAC: {sysProxyState.pacEnabled ? t('active ({{url}}) — takes precedence!', { url: sysProxyState.pacUrl }) : t('disabled')}
              </Badge>
            </Group>
            <Text size="xs" c="dimmed" mt={4}>
              {t('Primary service:')} <Code>{sysProxyState.primaryService || '?'}</Code>
              {sysProxyState.vpnService && (
                <>
                  {' '}· {t('Dynamic VPN service:')} <Code>{sysProxyState.vpnService}</Code>{' '}
                  · {t('VPN proxies:')}{' '}
                  <Code>
                    {sysProxyState.vpnHttpEnabled ? `${sysProxyState.vpnHttpProxy}:${sysProxyState.vpnHttpPort}` : t('HTTP off')}
                    {' / '}
                    {sysProxyState.vpnHttpsEnabled ? `${sysProxyState.vpnHttpsProxy}:${sysProxyState.vpnHttpsPort}` : t('HTTPS off')}
                    {sysProxyState.vpnPacEnabled ? ` / ${t('PAC ON')}` : ''}
                  </Code>
                </>
              )}
            </Text>
            <Text size="xs" c="dimmed" mt={4}>
              {t('Exclusions (bypass):')} {(sysProxyState.exceptions ?? []).join(', ') || t('none')}
            </Text>
            {sysProxyState.pacEnabled && (
              <Alert color="red" mt="sm" title={t('PAC active')}>
                {t('The PAC ({{url}}) takes precedence over the manual proxy: browsers will use it instead of this proxy. Enable "Reset system proxy" to disable it.', { url: sysProxyState.pacUrl })}
              </Alert>
            )}
          </>
        )}
          </Section>

          <Text size="xs" c="dimmed">
            {t('The configuration, including credentials and the relay private key, is encrypted in')}{' '}
            <Code>config.yml.enc</Code>{' '}
            {t('with the master password. On macOS the derived key can be unlocked with Touch ID through the Keychain.')}
          </Text>
        </Tabs.Panel>

        <Tabs.Panel value="routes">
          <Group justify="space-between" mb="md" align="flex-end">
            <Text size="sm" c="dimmed" maw={640}>
              {t('Routes describe how traffic leaves this computer: directly, through a corporate proxy, a PAC file, a chain of hops or the relay. The first applicable route wins unless you force one.')}
            </Text>
            <Button leftSection={<IconPlus size={16} />} onClick={openNew}>{t('Add')}</Button>
          </Group>
          <Card withBorder padding={0}>
            <Table.ScrollContainer minWidth={900}>
      <Table highlightOnHover style={{ border: 0, borderRadius: 0 }}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>{t('Name')}</Table.Th>
            <Table.Th>{t('Iface')}</Table.Th>
            <Table.Th>{t('Gateway')}</Table.Th>
            <Table.Th>{t('Net')}</Table.Th>
            <Table.Th>{t('PAC / Proxy')}</Table.Th>
            <Table.Th>{t('Applicable')}</Table.Th>
            <Table.Th>{t('PAC')}</Table.Th>
            <Table.Th />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {routes.map((r) => (
            <Table.Tr key={r.name}>
              <Table.Td>
                <Group gap={6} wrap="nowrap">
                  <Text fw={600}>{r.name}</Text>
                  {r.rulesOnly && <Badge size="xs" variant="light">{t('rules')}</Badge>}
                  {r.vpn === 'up' && <Badge size="xs" variant="light" color="grape" tt="none">{t('VPN connected')}</Badge>}
                  {r.vpn === 'down' && <Badge size="xs" variant="light" color="gray" tt="none">{t('No VPN')}</Badge>}
                </Group>
              </Table.Td>
              <Table.Td>
                {r.iface || '-'}
                {r.ifaceUp && <Text size="xs" c="dimmed">{t('in use')}: {r.ifaceUp}</Text>}
              </Table.Td>
              <Table.Td>{r.gateway || '-'}</Table.Td>
              <Table.Td>{r.net || '-'}</Table.Td>
              <Table.Td>
                <Text size="sm" truncate="end" maw={220}>{chainText(r, t)}</Text>
              </Table.Td>
              <Table.Td>
                <Tooltip label={r.whyNot || 'OK'} disabled={!r.whyNot}>
                  <Badge size="sm" color={r.applicable ? 'green' : 'red'} variant="light">
                    {r.applicable ? t('yes') : t('no')}
                  </Badge>
                </Tooltip>
              </Table.Td>
              <Table.Td>
                <Tooltip label={r.pacError || ''} disabled={!r.pacError}>
                  <Badge size="sm" color={pacColors[r.pacStatus] ?? 'gray'} variant="light">
                    {r.pacStatus}
                  </Badge>
                </Tooltip>
              </Table.Td>
              <Table.Td>
                <Group gap="xs" justify="flex-end">
                  <ActionIcon variant="subtle" color="gray" title={t('Move up')}
                    disabled={routePos(r.name) <= 0} onClick={() => moveRoute(r.name, -1)}>
                    <IconArrowUp size={16} />
                  </ActionIcon>
                  <ActionIcon variant="subtle" color="gray" title={t('Move down')}
                    disabled={routePos(r.name) < 0 || routePos(r.name) >= configRouteNames.length - 1}
                    onClick={() => moveRoute(r.name, 1)}>
                    <IconArrowDown size={16} />
                  </ActionIcon>
                  {r.pacStatus !== 'none' && (
                    <ActionIcon variant="subtle" color="blue" title={t('Reload PAC')}
                      onClick={() => api.refreshPac(r.name).then(load).catch((e) => setError(String(e)))}>
                      <IconRefresh size={16} />
                    </ActionIcon>
                  )}
                  <ActionIcon variant="subtle" color="blue" onClick={() => openEdit(r)} title={t('Edit')}>
                    <IconPencil size={16} />
                  </ActionIcon>
                  <ActionIcon variant="subtle" color="red" onClick={() => remove(r.name)} title={t('Delete')}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
            </Table.ScrollContainer>
          </Card>
        </Tabs.Panel>

        <Tabs.Panel value="hosts">
          <Section
            title={t('Fixed hosts')}
            description={t('Resolve a hostname to a fixed IP, ignoring DNS (useful for internal names that cannot be resolved through the VPN). Leave empty to use normal DNS.')}
            right={
              <Button size="xs" variant="light" leftSection={<IconPlus size={14} />}
                onClick={() => setHosts([...hosts, { host: '', ip: '' }])}>
                {t('Add')}
              </Button>
            }
          >
        <Stack gap="xs">
          {hosts.map((h, i) => (
            <Group key={i} gap="xs" align="flex-end">
              <TextInput style={{ flex: 2 }} label={i === 0 ? t('Host') : undefined}
                placeholder="repo.intra.example.com" value={h.host}
                onChange={(e) => setHostRow(i, { host: e.currentTarget.value })} />
              <TextInput style={{ flex: 1 }} label={i === 0 ? t('IP') : undefined}
                placeholder="192.0.2.40" value={h.ip}
                onChange={(e) => setHostRow(i, { ip: e.currentTarget.value })} />
              <ActionIcon variant="subtle" color="red" title={t('Remove')}
                onClick={() => setHosts(hosts.filter((_, j) => j !== i))}>
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          ))}
          {!hosts.length && <Text size="sm" c="dimmed">{t('No fixed hosts.')}</Text>}
        </Stack>
        <Group justify="flex-end" mt="sm">
          <Button variant="light" onClick={saveConfig}>{t('Save hosts')}</Button>
        </Group>
          </Section>

          <Section title={t('DNS cache ({{count}} entries)', { count: state?.dns.length ?? 0 })}>
          {state?.dns.length ? (
              <Table>
                <Table.Thead>
                  <Table.Tr><Table.Th>{t('Host')}</Table.Th><Table.Th>{t('IP')}</Table.Th></Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {state.dns.map((d) => (
                    <Table.Tr key={d.host}>
                      <Table.Td>{d.host}</Table.Td>
                      <Table.Td><Code>{d.ip || t('(unresolved)')}</Code></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            ) : (
              <Text c="dimmed" size="sm">{t('No entries')}</Text>
            )}
          </Section>
        </Tabs.Panel>

        <Tabs.Panel value="relay">
          <Section
            title={t('Relay')}
            description={t('mTLS connection configuration for the relay. To get the certificate by email use the Relay page; here you can also paste a manual certificate.')}
            right={
              <Badge color={relayCfg?.hasCertificate ? 'green' : 'gray'} variant="light">
                {relayCfg?.hasCertificate ? t('certificate present') : t('certificate missing')}
              </Badge>
            }
          >
        <SimpleGrid cols={{ base: 1, sm: 2 }} mb="sm">
          <TextInput label={t('mTLS address')} placeholder="relay.example.com:8443"
            value={relayAddress} onChange={(e) => setRelayAddress(e.currentTarget.value)} />
          <Select label={t('Route to reach the relay')} clearable placeholder={t('Automatic')}
            data={selectableRoutes.map((r) => ({ value: r.name, label: r.name }))}
            value={relayRoute || null} onChange={(v) => setRelayRoute(v ?? '')} />
        </SimpleGrid>
        <Switch label={t('Allow contacts to reach services on this machine')}
          description={t('AllowLocal: not recommended unless strictly necessary.')}
          checked={relayAllowLocal} onChange={(e) => setRelayAllowLocal(e.currentTarget.checked)} />
        <Group justify="space-between" mt="sm">
          <Text size="xs" c="dimmed">
            {relayCfg?.device ? <>{t('Device:')} <Code>{relayCfg.device}</Code> {t('(editable from the Relay page)')}</> : t('Device not yet assigned')}
          </Text>
          <Button variant="light" onClick={() => saveRelay(false)} disabled={!relayAddress.trim()}>
            {t('Save relay')}
          </Button>
        </Group>

        <Accordion mt="sm" variant="contained">
          <Accordion.Item value="cert">
            <Accordion.Control>
              <Text size="sm" fw={600}>{t('Manual certificate')}</Text>
            </Accordion.Control>
            <Accordion.Panel>
              <Stack gap="xs">
                <Text size="xs" c="dimmed">
                  {t('Leave empty to keep the current certificate. The content is saved only in the encrypted config and is no longer returned by the API.')}
                </Text>
                <Textarea label={t('Client certificate (PEM)')} minRows={3} value={relayCert}
                  onChange={(e) => setRelayCert(e.currentTarget.value)} autosize />
                <Textarea label={t('Client private key (PEM)')} minRows={3} value={relayKey}
                  onChange={(e) => setRelayKey(e.currentTarget.value)} autosize />
                <Textarea label={t('Relay CA (PEM, optional)')} minRows={2} value={relayCA}
                  onChange={(e) => setRelayCA(e.currentTarget.value)} autosize />
                <Group justify="space-between">
                  <Button variant="subtle" color="red"
                    onClick={() => window.confirm(t('Remove the relay certificate and key?')) && saveRelay(true)}
                    disabled={!relayCfg?.hasCertificate}>
                    {t('Remove certificate')}
                  </Button>
                  <Button onClick={() => saveRelay(false)}
                    disabled={(!relayCert && !relayKey && !relayCA) || !relayAddress.trim()}>
                    {t('Save certificate')}
                  </Button>
                </Group>
              </Stack>
            </Accordion.Panel>
          </Accordion.Item>
        </Accordion>
          </Section>
        </Tabs.Panel>
      </Tabs>

      <Modal opened={opened} onClose={close} title={editing ? t('Edit {{name}}', { name: editing.name }) : t('New route')} centered size="xl">
        <Stack gap="sm">
          <SimpleGrid cols={2}>
            <TextInput label={t('Name')} value={form.name}
              onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
            <TextInput label={t('Interface (optional)')} placeholder={t('e.g. utun4')}
              value={form.iface} onChange={(e) => setForm({ ...form, iface: e.currentTarget.value })} />
            <TextInput label={t('Gateway (optional)')} value={form.gateway}
              onChange={(e) => setForm({ ...form, gateway: e.currentTarget.value })} />
            <TextInput label={t('Network (optional)')} placeholder={t('e.g. 192.168.1.0/24')}
              value={form.net} onChange={(e) => setForm({ ...form, net: e.currentTarget.value })} />
            <Select label={t('VPN state (optional)')}
              description={t('Use the route only while a VPN is connected, or only while none is.')}
              placeholder={t('Any')} clearable
              data={[{ value: 'up', label: t('VPN connected') }, { value: 'down', label: t('No VPN') }]}
              value={form.vpn || null} onChange={(v) => setForm({ ...form, vpn: v ?? '' })} />
            <TextInput label={t('Interface in use (optional)')}
              description={t('Applies while a matching interface is up and carrying traffic, even if it is not the default route. Names or wildcards, comma-separated.')}
              placeholder="utun4, tun*, Pulse*"
              value={form.ifaceUp} onChange={(e) => setForm({ ...form, ifaceUp: e.currentTarget.value })} />
          </SimpleGrid>
          <Switch
            label={t('Rules only')}
            description={t('The route is used only when a destination rule points to it: it is not chosen automatically and does not appear among routes that can be forced. To connect to the relay, only the part of the chain before the relay hop is used.')}
            checked={form.rulesOnly}
            onChange={(e) => setForm({ ...form, rulesOnly: e.currentTarget.checked })}
          />
          <Divider label={t('Upstream (hops)')} labelPosition="left" mt="xs" />
          <Text size="xs" c="dimmed">
            {t('Traffic goes through the first hop, then the second through the first, and so on to the exit. Schemes: http://host:port, socks5://host:port, or relay://contact email: the chain stops at the relay hop (previous hops are used to reach the relay, subsequent ones go through the contact). A hop marked "Rules only" stops the chain if no rule selects the route. A PAC hop evaluates a PAC file and must be the only hop in the chain. A Dynamic hop evaluates the rules for the destination and applies the chosen route; if none matches it continues direct, and must be the last hop. Typing relay:// shows contacts and their devices; hops already used are also suggested.')}
          </Text>
          {form.hops.map((h, i) => {
            const kind = hopKind(h)
            const isDynamic = kind === 'dynamic'
            const isPac = kind === 'pac'
            return (
              <Paper key={i} withBorder p="xs" radius="sm">
                <Group gap="xs" wrap="nowrap" align="flex-end">
                  <Badge variant="light" size="lg" w={36} px={0}>{i + 1}</Badge>
                  <Select w={145} label={i === 0 ? t('Type') : undefined}
                    data={[
                      { value: 'proxy', label: t('Proxy / Relay') },
                      { value: 'pac', label: t('PAC') },
                      { value: 'dynamic', label: t('Dynamic') },
                    ]}
                    value={kind} allowDeselect={false}
                    onChange={(v) => v && setHopKind(i, v as HopKind)} />
                  {isDynamic ? (
                    <Text size="xs" c="dimmed" style={{ flex: 1, minWidth: 260 }} mb={8}>
                      {t('Evaluates the rules for the destination and applies the chosen route; if none matches it continues toward the target through the hops already traversed.')}
                    </Text>
                  ) : isPac ? (
                    <TextInput style={{ flex: 1, minWidth: 260 }} label={i === 0 ? t('PAC URL') : undefined}
                      placeholder="http://host/pac.pac"
                      value={h.pacUrl ?? ''} onChange={(e) => setHop(i, { pacUrl: e.currentTarget.value })} />
                  ) : (
                    <Autocomplete style={{ flex: 1, minWidth: 260 }} label={i === 0 ? t('Proxy') : undefined}
                      placeholder={t('http://host:8080, socks5://host:1080 or relay://contact/device')}
                      data={(h.proxyUrl ?? '').trim() ? hopSuggestions : []} limit={12}
                      value={h.proxyUrl ?? ''} onChange={(v) => setHop(i, { proxyUrl: v })} />
                  )}
                  {isDynamic ? (
                    <Text size="xs" c="dimmed" w={160} mb={8}>{t('rules only')}</Text>
                  ) : (
                    <Select w={160} label={i === 0 ? t('Credential') : undefined} placeholder={t('none')} clearable
                      data={credOptions} value={h.credential || null}
                      onChange={(v) => setHop(i, { credential: v ?? '' })} />
                  )}
                  <ActionIcon variant="subtle" color="red" title={t('Remove')}
                    onClick={() => setForm({ ...form, hops: form.hops.filter((_, j) => j !== i) })}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Group>
                <Group gap="md" mt={6} pl={48}>
                  <Tooltip label={isPac
                    ? t('With this option the PAC route is used only when a rule selects it')
                    : isDynamic
                      ? t('The route stops before the dynamic hop if no rule selects the route')
                      : t('The chain stops before this hop if no rule selects the route')}>
                    <Checkbox label={t('Rules only')} size="xs"
                      checked={h.rulesOnly ?? false}
                      onChange={(e) => setHop(i, { rulesOnly: e.currentTarget.checked })} />
                  </Tooltip>
                  <Group gap={4}>
                    <ActionIcon variant="subtle" color="gray" size="sm" disabled={i === 0 || isDynamic}
                      title={t('Move up')} onClick={() => moveHop(i, -1)}>
                      <IconArrowUp size={16} />
                    </ActionIcon>
                    <ActionIcon variant="subtle" color="gray" size="sm" disabled={i === form.hops.length - 1 || isDynamic}
                      title={t('Move down')} onClick={() => moveHop(i, 1)}>
                      <IconArrowDown size={16} />
                    </ActionIcon>
                  </Group>
                </Group>
              </Paper>
            )
          })}
          <Group>
            <Button variant="light" size="xs" leftSection={<IconPlus size={14} />}
              disabled={form.hops.some((h) => hopKind(h) !== 'proxy')}
              onClick={() => setForm({ ...form, hops: [...form.hops, { proxyUrl: '', credential: '', rulesOnly: false, kind: 'proxy' }] })}>
              {t('Add hop')}
            </Button>
          </Group>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>{t('Cancel')}</Button>
            <Button onClick={save} loading={busy}
              disabled={!form.name
                || form.hops.some((h) => {
                  const kind = hopKind(h)
                  return kind === 'pac'
                    ? !(h.pacUrl ?? '').trim()
                    : kind === 'proxy' ? !(h.proxyUrl ?? '').trim() : false
                })
                || (form.hops.some((h) => hopKind(h) === 'pac') && form.hops.length > 1)}>
              {t('Save')}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}
