import { useCallback, useEffect, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Button, Card, Checkbox, Code, Divider, Group, Modal, Select, SimpleGrid, Stack, Switch, Table,
  TagsInput, Text, TextInput, Title, Tooltip, Accordion,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconArrowDown, IconArrowUp, IconPencil, IconPlus, IconRefresh, IconTrash } from '@tabler/icons-react'
import { api } from '../api'
import type { Credential, Hop, RouteInfo, StateInfo, SystemProxyState } from '../api'

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
  if (r.chain?.length) {
    return r.chain
      .map((hop, i) => (r.hops?.[i]?.rulesOnly ? `${hop} (regole)` : hop))
      .join(' → ')
  }
  return r.pacUrl || r.proxyUrl || '-'
}

export default function ConfigPage() {
  const [state, setState] = useState<StateInfo | null>(null)
  const [creds, setCreds] = useState<Credential[]>([])
  const [error, setError] = useState<string | null>(null)
  const [address, setAddress] = useState('')
  const [socksAddress, setSocksAddress] = useState('')
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
    name: '', gateway: '', iface: '', net: '', pacUrl: '', proxyUrl: '', credential: '',
    hops: [] as Hop[], rulesOnly: false,
  })
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    api.state().then((s) => {
      setState(s)
      if (!configLoaded) {
        setAddress(s.address)
        setSocksAddress(s.socksAddress ?? '')
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
  }, [configLoaded])

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [load])

  const saveConfig = async () => {
    try {
      await api.saveConfig({ address, socksAddress, systemProxy: sysProxy, systemProxyExclude: exclude, pacHijack, pacHijackHost, forceChrome })
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
    setForm({ name: '', gateway: '', iface: '', net: '', pacUrl: '', proxyUrl: '', credential: '', hops: [], rulesOnly: false })
    open()
  }

  const openEdit = (r: RouteInfo) => {
    setEditing(r)
    setForm({
      name: r.name, gateway: r.gateway, iface: r.iface, net: r.net,
      pacUrl: r.pacUrl, proxyUrl: r.proxyUrl, credential: r.credential,
      hops: (r.hops ?? []).map((h) => ({ ...h, rulesOnly: h.rulesOnly ?? false })),
      rulesOnly: r.rulesOnly ?? false,
    })
    open()
  }

  const setHop = (i: number, patch: Partial<Hop>) =>
    setForm({ ...form, hops: form.hops.map((h, j) => (j === i ? { ...h, ...patch } : h)) })
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
  const credOptions = creds.map((c) => ({ value: c.name, label: c.name }))

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
            description="Vuota = automatica"
            style={{ minWidth: 220 }}
            clearable
            placeholder="Auto"
            data={routes.map((r) => ({ value: r.name, label: r.name }))}
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
            api.saveConfig({ address, socksAddress, systemProxy: sysProxy, systemProxyExclude: exclude, pacHijack: v, pacHijackHost, forceChrome })
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
            api.saveConfig({ address, socksAddress, systemProxy: v, systemProxyExclude: exclude, pacHijack, pacHijackHost, forceChrome })
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
            api.saveConfig({ address, socksAddress, systemProxy: sysProxy, systemProxyExclude: v, pacHijack, pacHijackHost, forceChrome })
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
            <Table.Th>Credential</Table.Th>
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
              <Table.Td>{r.credential || '-'}</Table.Td>
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
                  {r.pacUrl && (
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
            <Select label="Credential (opzionale)" clearable searchable
              data={credOptions} value={form.credential || null}
              onChange={(v) => setForm({ ...form, credential: v ?? '' })} />
            <TextInput label="Interfaccia (opzionale)" placeholder="es. utun4"
              value={form.iface} onChange={(e) => setForm({ ...form, iface: e.currentTarget.value })} />
            <TextInput label="Gateway (opzionale)" value={form.gateway}
              onChange={(e) => setForm({ ...form, gateway: e.currentTarget.value })} />
            <TextInput label="Network (opzionale)" placeholder="es. 192.168.1.0/24"
              value={form.net} onChange={(e) => setForm({ ...form, net: e.currentTarget.value })} />
            <TextInput label="Proxy upstream (opzionale)" placeholder="host:porta"
              disabled={form.hops.length > 0}
              value={form.proxyUrl} onChange={(e) => setForm({ ...form, proxyUrl: e.currentTarget.value })} />
          </SimpleGrid>
          <TextInput label="PAC URL (opzionale)" placeholder="http://host/pac.pac"
            disabled={form.hops.length > 0}
            value={form.pacUrl} onChange={(e) => setForm({ ...form, pacUrl: e.currentTarget.value })} />
          <Switch
            label="Solo per regole"
            description="La route è usata solo quando una regola di destinazione la indica: non viene scelta automaticamente per il traffico. Per collegarsi al relay viene usata solo la parte della catena che precede l'hop relay."
            checked={form.rulesOnly}
            onChange={(e) => setForm({ ...form, rulesOnly: e.currentTarget.checked })}
          />
          <Divider label="Catena di proxy (opzionale)" labelPosition="left" mt="xs" />
          <Text size="xs" c="dimmed">
            Il traffico passa dal primo proxy, poi dal secondo attraverso il primo, e così via fino all'uscita.
            Con una catena, PAC e proxy upstream sono ignorati. Schemi: http://host:porta, socks5://host:porta, oppure relay://email del contatto: la catena si ferma all'hop relay (i salti precedenti servono a raggiungere il relay, quelli successivi passano dal contatto). Un salto marcato "Solo regole" ferma la catena se nessuna regola seleziona la route.
          </Text>
          {form.hops.map((h, i) => (
            <Group key={i} gap="xs" wrap="nowrap" align="flex-end">
              <Badge variant="light" size="lg" w={36} px={0}>{i + 1}</Badge>
              <TextInput style={{ flex: 1 }} label={i === 0 ? 'Proxy' : undefined} placeholder="http://host:8080 o socks5://host:1080"
                value={h.proxyUrl} onChange={(e) => setHop(i, { proxyUrl: e.currentTarget.value })} />
              <Select w={170} label={i === 0 ? 'Credential' : undefined} placeholder="nessuna" clearable
                data={credOptions} value={h.credential || null}
                onChange={(v) => setHop(i, { credential: v ?? '' })} />
              <Tooltip label="La catena si ferma prima di questo salto se nessuna regola seleziona la route">
                <Checkbox label="Solo regole" size="xs" mb={6}
                  checked={h.rulesOnly ?? false}
                  onChange={(e) => setHop(i, { rulesOnly: e.currentTarget.checked })} />
              </Tooltip>
              <ActionIcon variant="subtle" color="gray" disabled={i === 0} title="Sposta su" onClick={() => moveHop(i, -1)}>
                <IconArrowUp size={16} />
              </ActionIcon>
              <ActionIcon variant="subtle" color="gray" disabled={i === form.hops.length - 1} title="Sposta giù" onClick={() => moveHop(i, 1)}>
                <IconArrowDown size={16} />
              </ActionIcon>
              <ActionIcon variant="subtle" color="red" title="Rimuovi" onClick={() => setForm({ ...form, hops: form.hops.filter((_, j) => j !== i) })}>
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          ))}
          <Group>
            <Button variant="light" size="xs" leftSection={<IconPlus size={14} />}
              onClick={() => setForm({ ...form, hops: [...form.hops, { proxyUrl: '', credential: '', rulesOnly: false }] })}>
              Aggiungi proxy
            </Button>
          </Group>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>Annulla</Button>
            <Button onClick={save} loading={busy} disabled={!form.name || form.hops.some((h) => !h.proxyUrl.trim())}>Salva</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}
