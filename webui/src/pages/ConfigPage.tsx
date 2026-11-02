import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  ActionIcon, Alert, Autocomplete, Badge, Button, Card, Checkbox, Code, Divider, Group, Modal, Select, SimpleGrid, Stack, Switch, Table,
  TagsInput, Text, Textarea, TextInput, Title, Tooltip, Accordion,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconArrowDown, IconArrowUp, IconPencil, IconPlus, IconRefresh, IconTrash } from '@tabler/icons-react'
import { api } from '../api'
import type { Credential, Hop, RelayConfigInfo, RelayStatus, RouteInfo, StateInfo, SystemProxyState } from '../api'

const pacColors: Record<string, string> = {
  none: 'gray',
  loaded: 'green',
  loading: 'yellow',
  error: 'red',
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <Text size="xs" c="dimmed">{label}</Text>
      <Text size="sm">{value || '-'}</Text>
    </div>
  )
}

function chainText(r: RouteInfo) {
  if (r.hops?.length) {
    return r.hops
      .map((h, i) => {
        const text = h.dynamic
          ? 'dinamico'
          : h.pacUrl
            ? `pac ${h.pacUrl}`
            : (r.chain?.[i] ?? h.proxyUrl ?? '')
        return h.rulesOnly ? `${text} (regole)` : text
      })
      .join(' → ')
  }
  return r.chain?.length ? r.chain.join(' → ') : '-'
}

export default function ConfigPage() {
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
  const [pacHijack, setPacHijack] = useState(false)
  const [pacHijackHost, setPacHijackHost] = useState('wpad')
  const [forceChrome, setForceChrome] = useState(false)
  const [sysProxyState, setSysProxyState] = useState<SystemProxyState | null>(null)
  const [forceRoute, setForceRoute] = useState<string>('')
  const [configLoaded, setConfigLoaded] = useState(false)
  const [opened, { open, close }] = useDisclosure(false)
  const [editing, setEditing] = useState<RouteInfo | null>(null)
  const [form, setForm] = useState({
    name: '', gateway: '', iface: '', net: '',
    hops: [] as Hop[], rulesOnly: false,
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
        setPacHijack(s.pacHijack)
        setPacHijackHost(s.pacHijackHost || 'wpad')
        setForceChrome(s.forceChrome)
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
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
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
        pacHijack,
        pacHijackHost,
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
    setForm({ name: '', gateway: '', iface: '', net: '', hops: [], rulesOnly: false })
    open()
  }

  const openEdit = (r: RouteInfo) => {
    setEditing(r)
    setForm({
      name: r.name, gateway: r.gateway, iface: r.iface, net: r.net,
      hops: (r.hops ?? []).map((h) => ({
        proxyUrl: h.proxyUrl ?? '',
        pacUrl: h.pacUrl ?? '',
        dynamic: h.dynamic ?? false,
        credential: h.credential ?? '',
        rulesOnly: h.rulesOnly ?? false,
      })),
      rulesOnly: r.rulesOnly ?? false,
    })
    open()
  }

  const setHop = (i: number, patch: Partial<Hop>) =>
    setForm({ ...form, hops: form.hops.map((h, j) => (j === i ? { ...h, ...patch } : h)) })
  const setHopKind = (i: number, kind: string) => {
    const hop = form.hops[i]
    if (kind === 'pac') {
      // A PAC is not a proxy: it must be the only hop of the chain.
      setForm({
        ...form,
        hops: [{ proxyUrl: '', pacUrl: hop.pacUrl ?? '', dynamic: false, credential: hop.credential, rulesOnly: hop.rulesOnly }],
      })
    } else if (kind === 'dynamic') {
      // A dynamic hop is terminal: keep the prefix and drop what came after.
      setForm({
        ...form,
        hops: [
          ...form.hops.slice(0, i),
          { proxyUrl: '', pacUrl: '', dynamic: true, credential: '', rulesOnly: hop.rulesOnly },
        ],
      })
    } else {
      setHop(i, { pacUrl: '', dynamic: false })
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
      await api.saveRoute(form)
      close()
      load()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (name: string) => {
    if (!window.confirm(`Eliminare la route "${name}"?`)) return
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
      <Title order={3} mb="md">Configurazione</Title>
      {error && <Alert color="red" mb="md">Errore: {error}</Alert>}

      <Card withBorder mb="lg">
        <Text fw={700} mb="sm">Rete</Text>
        <SimpleGrid cols={{ base: 1, sm: 3, md: 5 }}>
          <Info label="Interfaccia corrente" value={state?.iface ?? ''} />
          <Info label="Gateway" value={state?.gateway ?? ''} />
          <Info label="Network" value={state?.network ?? ''} />
          <Info label="Uptime" value={state ? `${Math.floor(state.uptimeSeconds / 60)}m` : ''} />
          <Info label="Connessioni attive" value={String(state?.activeConns ?? 0)} />
        </SimpleGrid>
        <Group mt="md" align="flex-end">
          <TextInput
            label="Indirizzo di ascolto"
            description="Il riavvio del listener è automatico"
            style={{ minWidth: 220 }}
            value={address}
            onChange={(e) => setAddress(e.currentTarget.value)}
          />
          <TextInput
            label="SOCKS5"
            description="Vuoto = disabilitato"
            placeholder="127.0.0.1:1080"
            style={{ minWidth: 200 }}
            value={socksAddress}
            onChange={(e) => setSocksAddress(e.currentTarget.value)}
          />
          <Button onClick={saveConfig} disabled={!address}>Salva</Button>
          <Select
            label="Route forzata"
            description="Vuota = automatica. Le regole di destinazione sono valutate solo in Auto."
            style={{ minWidth: 220 }}
            clearable
            placeholder="Auto"
            data={selectableRoutes.map((r) => ({ value: r.name, label: r.name }))}
            value={forceRoute || null}
            onChange={(v) => applyForceRoute(v)}
          />
        </Group>
        <Switch
          mt="md"
          label="PAC hijack (wpad)"
          description="La VPN impone il PAC aziendale (http://wpad/wpad.dat): il proxy lo serve lui stesso su porta 80 e fa risolvere l'host a 127.0.0.1, così i browser passano dal proxy senza mai toccare le impostazioni della VPN (serve sudo)"
          checked={pacHijack}
          onChange={(e) => {
            const v = e.currentTarget.checked
            setPacHijack(v)
            api.saveConfig({ address, socksAddress, hosts: hostsObject(), systemProxy: sysProxy, systemProxyExclude: exclude, pacHijack: v, pacHijackHost, forceChrome })
              .then(load)
              .catch((err) => setError(String(err)))
          }}
        />
        {pacHijack && (
          <TextInput
            mt="xs"
            label="Host del PAC da intercettare"
            description="Voce aggiunta a /etc/hosts (default: wpad)"
            style={{ maxWidth: 280 }}
            value={pacHijackHost}
            onChange={(e) => setPacHijackHost(e.currentTarget.value)}
            onBlur={saveConfig}
          />
        )}
        <Switch
          mt="md"
          label="Reimposta proxy di sistema al cambio rete"
          description="Con Pulse connesso riscrive solo lo stato runtime del servizio Pulse (via scutil, nessun conflitto né riconnessioni); senza VPN usa networksetup"
          checked={sysProxy}
          onChange={(e) => {
            const v = e.currentTarget.checked
            setSysProxy(v)
            api.saveConfig({ address, socksAddress, hosts: hostsObject(), systemProxy: v, systemProxyExclude: exclude, pacHijack, pacHijackHost, forceChrome })
              .then(load)
              .catch((err) => setError(String(err)))
          }}
        />
        <TagsInput
          mt="md"
          label="Esclusioni proxy di sistema"
          description="Interfacce o nomi di servizio da non toccare (es. utun4, VPN): evita il conflitto col client VPN che riconnette in continuazione"
          placeholder="utun4"
          value={exclude}
          onChange={(v) => {
            setExclude(v)
            api.saveConfig({ address, socksAddress, hosts: hostsObject(), systemProxy: sysProxy, systemProxyExclude: v, pacHijack, pacHijackHost, forceChrome })
              .then(load)
              .catch((err) => setError(String(err)))
          }}
        />
        {sysProxyState && (
          <>
            <Group gap="xs" mt="sm">
              <Text size="sm" fw={600}>Proxy di sistema effettivo (visto da Chrome):</Text>
              <Badge
                color={sysProxyState.httpEnabled && sysProxyState.httpProxy ? 'green' : 'red'}
                variant="light"
              >
                HTTP: {sysProxyState.httpEnabled ? `${sysProxyState.httpProxy}:${sysProxyState.httpPort}` : 'disabilitato'}
              </Badge>
              <Badge
                color={sysProxyState.httpsEnabled && sysProxyState.httpsProxy ? 'green' : 'red'}
                variant="light"
              >
                HTTPS: {sysProxyState.httpsEnabled ? `${sysProxyState.httpsProxy}:${sysProxyState.httpsPort}` : 'disabilitato'}
              </Badge>
              <Badge color={sysProxyState.pacEnabled ? 'red' : 'gray'} variant="light">
                PAC: {sysProxyState.pacEnabled ? `attivo (${sysProxyState.pacUrl}) — ha la precedenza!` : 'disattivato'}
              </Badge>
            </Group>
            <Text size="xs" c="dimmed" mt={4}>
              Servizio primario: <Code>{sysProxyState.primaryService || '?'}</Code>
              {sysProxyState.vpnService && (
                <>
                  {' '}· Servizio VPN dinamico: <Code>{sysProxyState.vpnService}</Code>{' '}
                  · Proxies VPN:{' '}
                  <Code>
                    {sysProxyState.vpnHttpEnabled ? `${sysProxyState.vpnHttpProxy}:${sysProxyState.vpnHttpPort}` : 'HTTP off'}
                    {' / '}
                    {sysProxyState.vpnHttpsEnabled ? `${sysProxyState.vpnHttpsProxy}:${sysProxyState.vpnHttpsPort}` : 'HTTPS off'}
                    {sysProxyState.vpnPacEnabled ? ' / PAC ON' : ''}
                  </Code>
                </>
              )}
            </Text>
            <Text size="xs" c="dimmed" mt={4}>
              Eccezioni (bypass): {(sysProxyState.exceptions ?? []).join(', ') || 'nessuna'}
            </Text>
            {sysProxyState.pacEnabled && (
              <Alert color="red" mt="sm" title="PAC attivo">
                Il PAC ({sysProxyState.pacUrl}) ha la precedenza sul proxy manuale: i browser lo useranno
                al posto di questo proxy. Attiva "Reimposta proxy di sistema" per disattivarlo.
              </Alert>
            )}
          </>
        )}
        <Text size="xs" c="dimmed" mt="sm">
          La configurazione, incluse le credenziali e la chiave privata del relay, è cifrata in{' '}
          <Code>config.yml.enc</Code> con la master password. Su macOS la chiave derivata può essere
          sbloccata con Touch ID tramite il Keychain.
        </Text>
      </Card>

      <Card withBorder mb="lg">
        <Group justify="space-between" mb="xs">
          <div>
            <Text fw={700}>Host fissi</Text>
            <Text size="xs" c="dimmed">
              Risolvi un hostname a un IP fisso, ignorando il DNS (utile per nomi interni non
              risolvibili dalla VPN). Lascia vuoto per usare il DNS normale.
            </Text>
          </div>
          <Button size="xs" leftSection={<IconPlus size={14} />}
            onClick={() => setHosts([...hosts, { host: '', ip: '' }])}>
            Aggiungi
          </Button>
        </Group>
        <Stack gap="xs">
          {hosts.map((h, i) => (
            <Group key={i} gap="xs" align="flex-end">
              <TextInput style={{ flex: 2 }} label={i === 0 ? 'Host' : undefined}
                placeholder="repo.intra.example.com" value={h.host}
                onChange={(e) => setHostRow(i, { host: e.currentTarget.value })} />
              <TextInput style={{ flex: 1 }} label={i === 0 ? 'IP' : undefined}
                placeholder="192.0.2.40" value={h.ip}
                onChange={(e) => setHostRow(i, { ip: e.currentTarget.value })} />
              <ActionIcon variant="subtle" color="red" title="Rimuovi"
                onClick={() => setHosts(hosts.filter((_, j) => j !== i))}>
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          ))}
          {!hosts.length && <Text size="sm" c="dimmed">Nessun host fisso.</Text>}
        </Stack>
        <Group justify="flex-end" mt="sm">
          <Button variant="light" onClick={saveConfig}>Salva host</Button>
        </Group>
      </Card>

      <Card withBorder mb="lg">
        <Group justify="space-between" mb="xs">
          <div>
            <Text fw={700}>Relay</Text>
            <Text size="xs" c="dimmed">
              Configurazione della connessione mTLS al relay. Per ottenere il certificato via
              e-mail usa la pagina Relay; qui puoi anche incollare un certificato manuale.
            </Text>
          </div>
          <Badge color={relayCfg?.hasCertificate ? 'green' : 'gray'} variant="light">
            certificato {relayCfg?.hasCertificate ? 'presente' : 'assente'}
          </Badge>
        </Group>
        <SimpleGrid cols={{ base: 1, sm: 2 }} mb="sm">
          <TextInput label="Indirizzo mTLS" placeholder="relay.example.com:8443"
            value={relayAddress} onChange={(e) => setRelayAddress(e.currentTarget.value)} />
          <Select label="Route per raggiungere il relay" clearable placeholder="Automatica"
            data={selectableRoutes.map((r) => ({ value: r.name, label: r.name }))}
            value={relayRoute || null} onChange={(v) => setRelayRoute(v ?? '')} />
        </SimpleGrid>
        <Switch label="Consenti ai contatti di raggiungere servizi su questa macchina"
          description="AllowLocal: sconsigliato se non strettamente necessario."
          checked={relayAllowLocal} onChange={(e) => setRelayAllowLocal(e.currentTarget.checked)} />
        <Group justify="space-between" mt="sm">
          <Text size="xs" c="dimmed">
            {relayCfg?.device ? <>Device: <Code>{relayCfg.device}</Code> (modificabile dalla pagina Relay)</> : 'Device non ancora assegnato'}
          </Text>
          <Button variant="light" onClick={() => saveRelay(false)} disabled={!relayAddress.trim()}>
            Salva relay
          </Button>
        </Group>

        <Accordion mt="sm" variant="contained">
          <Accordion.Item value="cert">
            <Accordion.Control>
              <Text size="sm" fw={600}>Certificato manuale</Text>
            </Accordion.Control>
            <Accordion.Panel>
              <Stack gap="xs">
                <Text size="xs" c="dimmed">
                  Lascia vuoto per mantenere il certificato attuale. Il contenuto viene salvato
                  solo nel config cifrato e non viene più restituito dall'API.
                </Text>
                <Textarea label="Certificato client (PEM)" minRows={3} value={relayCert}
                  onChange={(e) => setRelayCert(e.currentTarget.value)} autosize />
                <Textarea label="Chiave privata client (PEM)" minRows={3} value={relayKey}
                  onChange={(e) => setRelayKey(e.currentTarget.value)} autosize />
                <Textarea label="CA del relay (PEM, opzionale)" minRows={2} value={relayCA}
                  onChange={(e) => setRelayCA(e.currentTarget.value)} autosize />
                <Group justify="space-between">
                  <Button variant="subtle" color="red"
                    onClick={() => window.confirm('Rimuovere il certificato e la chiave del relay?') && saveRelay(true)}
                    disabled={!relayCfg?.hasCertificate}>
                    Rimuovi certificato
                  </Button>
                  <Button onClick={() => saveRelay(false)}
                    disabled={(!relayCert && !relayKey && !relayCA) || !relayAddress.trim()}>
                    Salva certificato
                  </Button>
                </Group>
              </Stack>
            </Accordion.Panel>
          </Accordion.Item>
        </Accordion>
      </Card>

      <Group justify="space-between" mb="sm">
        <Title order={4}>Route</Title>
        <Button leftSection={<IconPlus size={16} />} onClick={openNew}>Aggiungi</Button>
      </Group>

      <Table striped highlightOnHover withTableBorder>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Nome</Table.Th>
            <Table.Th>Iface</Table.Th>
            <Table.Th>Gateway</Table.Th>
            <Table.Th>Net</Table.Th>
            <Table.Th>PAC / Proxy</Table.Th>
            <Table.Th>Applicabile</Table.Th>
            <Table.Th>PAC</Table.Th>
            <Table.Th />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {routes.map((r) => (
            <Table.Tr key={r.name}>
              <Table.Td>
                <Group gap={6} wrap="nowrap">
                  <Text fw={600}>{r.name}</Text>
                  {r.rulesOnly && <Badge size="xs" variant="light">regole</Badge>}
                </Group>
              </Table.Td>
              <Table.Td>{r.iface || '-'}</Table.Td>
              <Table.Td>{r.gateway || '-'}</Table.Td>
              <Table.Td>{r.net || '-'}</Table.Td>
              <Table.Td>
                <Text size="sm" truncate="end" maw={220}>{chainText(r)}</Text>
              </Table.Td>
              <Table.Td>
                <Tooltip label={r.whyNot || 'OK'} disabled={!r.whyNot}>
                  <Badge size="sm" color={r.applicable ? 'green' : 'red'} variant="light">
                    {r.applicable ? 'sì' : 'no'}
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
                  <ActionIcon variant="subtle" color="gray" title="Sposta su"
                    disabled={routePos(r.name) <= 0} onClick={() => moveRoute(r.name, -1)}>
                    <IconArrowUp size={16} />
                  </ActionIcon>
                  <ActionIcon variant="subtle" color="gray" title="Sposta giù"
                    disabled={routePos(r.name) < 0 || routePos(r.name) >= configRouteNames.length - 1}
                    onClick={() => moveRoute(r.name, 1)}>
                    <IconArrowDown size={16} />
                  </ActionIcon>
                  {r.pacStatus !== 'none' && (
                    <ActionIcon variant="subtle" color="blue" title="Ricaricare il PAC"
                      onClick={() => api.refreshPac(r.name).then(load).catch((e) => setError(String(e)))}>
                      <IconRefresh size={16} />
                    </ActionIcon>
                  )}
                  <ActionIcon variant="subtle" color="blue" onClick={() => openEdit(r)} title="Modifica">
                    <IconPencil size={16} />
                  </ActionIcon>
                  <ActionIcon variant="subtle" color="red" onClick={() => remove(r.name)} title="Elimina">
                    <IconTrash size={16} />
                  </ActionIcon>
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>

      <Accordion mt="lg" variant="separated">
        <Accordion.Item value="dns">
          <Accordion.Control>
            <Text fw={600}>Cache DNS ({state?.dns.length ?? 0} voci)</Text>
          </Accordion.Control>
          <Accordion.Panel>
            {state?.dns.length ? (
              <Table striped withTableBorder>
                <Table.Thead>
                  <Table.Tr><Table.Th>Host</Table.Th><Table.Th>IP</Table.Th></Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {state.dns.map((d) => (
                    <Table.Tr key={d.host}>
                      <Table.Td>{d.host}</Table.Td>
                      <Table.Td><Code>{d.ip || '(non risolto)'}</Code></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            ) : (
              <Text c="dimmed" size="sm">Nessuna voce</Text>
            )}
          </Accordion.Panel>
        </Accordion.Item>
      </Accordion>

      <Modal opened={opened} onClose={close} title={editing ? `Modifica ${editing.name}` : 'Nuova route'} centered size="lg">
        <Stack gap="sm">
          <SimpleGrid cols={2}>
            <TextInput label="Nome" value={form.name}
              onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
            <TextInput label="Interfaccia (opzionale)" placeholder="es. utun4"
              value={form.iface} onChange={(e) => setForm({ ...form, iface: e.currentTarget.value })} />
            <TextInput label="Gateway (opzionale)" value={form.gateway}
              onChange={(e) => setForm({ ...form, gateway: e.currentTarget.value })} />
            <TextInput label="Network (opzionale)" placeholder="es. 192.168.1.0/24"
              value={form.net} onChange={(e) => setForm({ ...form, net: e.currentTarget.value })} />
          </SimpleGrid>
          <Switch
            label="Solo per regole"
            description="La route è usata solo quando una regola di destinazione la indica: non viene scelta automaticamente né appare tra le route forzabili. Per collegarsi al relay viene usata solo la parte della catena che precede l'hop relay."
            checked={form.rulesOnly}
            onChange={(e) => setForm({ ...form, rulesOnly: e.currentTarget.checked })}
          />
          <Divider label="Upstream (salti)" labelPosition="left" mt="xs" />
          <Text size="xs" c="dimmed">
            Il traffico passa dal primo salto, poi dal secondo attraverso il primo, e così via fino all'uscita.
            Schemi: http://host:porta, socks5://host:porta, oppure relay://email del contatto: la catena si ferma all'hop relay (i salti precedenti servono a raggiungere il relay, quelli successivi passano dal contatto). Un salto marcato "Solo regole" ferma la catena se nessuna regola seleziona la route. Un salto PAC valuta un file PAC e deve essere l'unico salto della catena. Un salto Dinamico valuta le regole per la destinazione e applica la route scelta; se nessuna corrisponde prosegue diretto, e deve essere l'ultimo salto. Scrivendo relay:// compaiono i contatti e i loro device; sono suggeriti anche i salti già usati.
          </Text>
          {form.hops.map((h, i) => {
            const isDynamic = Boolean(h.dynamic)
            const isPac = Boolean(h.pacUrl)
            return (
              <Group key={i} gap="xs" wrap="nowrap" align="flex-end">
                <Badge variant="light" size="lg" w={36} px={0}>{i + 1}</Badge>
                <Select w={150} label={i === 0 ? 'Tipo' : undefined}
                  data={[
                    { value: 'proxy', label: 'Proxy / Relay' },
                    { value: 'pac', label: 'PAC' },
                    { value: 'dynamic', label: 'Dinamico' },
                  ]}
                  value={isDynamic ? 'dynamic' : isPac ? 'pac' : 'proxy'} allowDeselect={false}
                  onChange={(v) => v && setHopKind(i, v)} />
                {isDynamic ? (
                  <Text size="xs" c="dimmed" style={{ flex: 1 }} mb={8}>
                    Valuta le regole per la destinazione e applica la route scelta; se nessuna corrisponde prosegue diretto.
                  </Text>
                ) : isPac ? (
                  <TextInput style={{ flex: 1 }} label={i === 0 ? 'PAC URL' : undefined}
                    placeholder="http://host/pac.pac"
                    value={h.pacUrl ?? ''} onChange={(e) => setHop(i, { pacUrl: e.currentTarget.value })} />
                ) : (
                  <Autocomplete style={{ flex: 1 }} label={i === 0 ? 'Proxy' : undefined}
                    placeholder="http://host:8080, socks5://host:1080 o relay://contatto/device"
                    data={(h.proxyUrl ?? '').trim() ? hopSuggestions : []} limit={12}
                    value={h.proxyUrl ?? ''} onChange={(v) => setHop(i, { proxyUrl: v })} />
                )}
                {isDynamic ? (
                  <Text size="xs" c="dimmed" w={170} mb={8}>solo regole</Text>
                ) : (
                  <Select w={170} label={i === 0 ? 'Credential' : undefined} placeholder="nessuna" clearable
                    data={credOptions} value={h.credential || null}
                    onChange={(v) => setHop(i, { credential: v ?? '' })} />
                )}
                <Tooltip label={isPac
                  ? 'Con questa opzione la route PAC è usata solo quando una regola la seleziona'
                  : isDynamic
                    ? 'La route si ferma prima del salto dinamico se nessuna regola seleziona la route'
                    : 'La catena si ferma prima di questo salto se nessuna regola seleziona la route'}>
                  <Checkbox label="Solo regole" size="xs" mb={6}
                    checked={h.rulesOnly ?? false}
                    onChange={(e) => setHop(i, { rulesOnly: e.currentTarget.checked })} />
                </Tooltip>
                <ActionIcon variant="subtle" color="gray" disabled={i === 0 || isDynamic} title="Sposta su" onClick={() => moveHop(i, -1)}>
                  <IconArrowUp size={16} />
                </ActionIcon>
                <ActionIcon variant="subtle" color="gray" disabled={i === form.hops.length - 1 || isDynamic} title="Sposta giù" onClick={() => moveHop(i, 1)}>
                  <IconArrowDown size={16} />
                </ActionIcon>
                <ActionIcon variant="subtle" color="red" title="Rimuovi" onClick={() => setForm({ ...form, hops: form.hops.filter((_, j) => j !== i) })}>
                  <IconTrash size={16} />
                </ActionIcon>
              </Group>
            )
          })}
          <Group>
            <Button variant="light" size="xs" leftSection={<IconPlus size={14} />}
              disabled={form.hops.some((h) => h.pacUrl || h.dynamic)}
              onClick={() => setForm({ ...form, hops: [...form.hops, { proxyUrl: '', credential: '', rulesOnly: false }] })}>
              Aggiungi salto
            </Button>
          </Group>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>Annulla</Button>
            <Button onClick={save} loading={busy}
              disabled={!form.name
                || form.hops.some((h) => h.dynamic ? false : h.pacUrl ? !h.pacUrl.trim() : !(h.proxyUrl ?? '').trim())
                || (form.hops.some((h) => h.pacUrl) && form.hops.length > 1)}>
              Salva
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}
