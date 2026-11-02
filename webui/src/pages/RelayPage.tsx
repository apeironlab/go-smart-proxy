import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Button, Card, Code, Group, Modal, Stack, Table, Text, Textarea, TextInput, Title,
} from '@mantine/core'
import { IconCheck, IconPencil, IconPlus, IconTrash, IconX } from '@tabler/icons-react'
import { api, ApiError } from '../api'
import type { CertificatePrompt, RelayStatus } from '../api'

const formatFingerprint = (fp: string) =>
  fp.replace(/(..)(?!$)/g, '$1:').toUpperCase()

export default function RelayPage() {
  const [st, setSt] = useState<RelayStatus | null>(null)
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [deviceOpen, setDeviceOpen] = useState(false)
  const [deviceValue, setDeviceValue] = useState('')
  const [enrollAddress, setEnrollAddress] = useState('')
  const [enrollEmail, setEnrollEmail] = useState('')
  const [enrollCA, setEnrollCA] = useState('')
  const [enrollCode, setEnrollCode] = useState('')
  const [enrollPhase, setEnrollPhase] = useState<'form' | 'code'>('form')
  const [showEnroll, setShowEnroll] = useState(false)
  const [busy, setBusy] = useState(false)
  const [certPrompt, setCertPrompt] = useState<CertificatePrompt | null>(null)
  const enrollRestored = useRef(false)

  const load = useCallback(() => {
    api.relay().then(setSt).catch((e) => setError(String(e)))
    api.relayEnrollStatus().then((s) => {
      if (s.pending && s.email && !enrollRestored.current) {
        enrollRestored.current = true
        setEnrollEmail(s.email)
        setEnrollAddress(s.address ?? '')
        setEnrollPhase('code')
        setShowEnroll(true)
      }
    }).catch(() => {})
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 2000)
    return () => clearInterval(t)
  }, [load])

  const run = async (fn: () => Promise<unknown>) => {
    try {
      setError(null)
      await fn()
      load()
    } catch (e) {
      setError(String(e))
    }
  }

  const saveDevice = async () => {
    await run(() => api.relaySetDevice(deviceValue.trim()))
    setDeviceOpen(false)
  }

  const requestEnrollment = async (acceptFingerprint = '') => {
    setBusy(true)
    try {
      setError(null)
      await api.relayEnroll(enrollAddress.trim(), enrollEmail.trim(), enrollCA.trim(), acceptFingerprint)
      setCertPrompt(null)
      setEnrollPhase('code')
    } catch (e) {
      if (e instanceof ApiError) {
        const cert = (e.payload as { certificate?: CertificatePrompt } | undefined)?.certificate
        if (cert) {
          setCertPrompt(cert)
          return
        }
      }
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const confirmEnrollment = async () => {
    setBusy(true)
    try {
      setError(null)
      await api.relayConfirm(enrollCode.trim())
      setEnrollPhase('form')
      setShowEnroll(false)
      setEnrollCode('')
      load()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  if (!st) return null
  if (!st.enabled || showEnroll) {
    return (
      <Stack>
        <Title order={3}>Relay</Title>
        {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}
        {enrollPhase === 'form' ? (
          <Card withBorder>
            <Text fw={700} mb="xs">Collega questo dispositivo al relay</Text>
            <Text size="sm" c="dimmed" mb="sm">
              Inserisci l'indirizzo dell'endpoint di enrollment e la tua e-mail. Il relay invierà un
              codice di conferma; il certificato verrà creato localmente e firmato dal relay.
            </Text>
            <Stack gap="sm">
              <TextInput label="Indirizzo relay (enrollment)" placeholder="relay.example.com:8444"
                value={enrollAddress} onChange={(e) => setEnrollAddress(e.currentTarget.value)} />
              <TextInput label="E-mail" placeholder="nome@dominio.it"
                value={enrollEmail} onChange={(e) => setEnrollEmail(e.currentTarget.value)} />
              <Textarea label="CA per l'endpoint di enrollment (opzionale, PEM)"
                description="Serve solo se l'endpoint HTTPS di enrollment usa una CA interna. La CA del relay mTLS viene fornita dal relay."
                minRows={3} value={enrollCA} onChange={(e) => setEnrollCA(e.currentTarget.value)} />
              <Group justify="flex-end">
                {st.enabled && <Button variant="subtle" onClick={() => setShowEnroll(false)}>Annulla</Button>}
                <Button onClick={() => requestEnrollment()} loading={busy}
                  disabled={!enrollAddress.trim() || !enrollEmail.trim()}>
                  Invia richiesta
                </Button>
              </Group>
            </Stack>
          </Card>
        ) : (
          <Card withBorder>
            <Text fw={700} mb="xs">Codice inviato a {enrollEmail}</Text>
            <Text size="sm" c="dimmed" mb="sm">
              Controlla l'e-mail e inserisci qui il codice di conferma. Il codice scade dopo 15 minuti.
            </Text>
            <Group gap="xs" align="flex-end">
              <TextInput label="Codice" placeholder="ABCD-EFGH" value={enrollCode}
                onChange={(e) => setEnrollCode(e.currentTarget.value)}
                onKeyDown={(e) => e.key === 'Enter' && enrollCode.trim() && confirmEnrollment()} />
              <Button onClick={confirmEnrollment} loading={busy} disabled={!enrollCode.trim()}>Conferma</Button>
              <Button variant="subtle" onClick={() => setEnrollPhase('form')}>Indietro</Button>
            </Group>
          </Card>
        )}

        <Modal opened={!!certPrompt} onClose={() => setCertPrompt(null)}
          title="Certificato non riconosciuto" centered size="lg">
          {certPrompt && (
            <Stack gap="sm">
              <Alert color="yellow">
                La CA di questo certificato non è conosciuta. Verifica il fingerprint con
                l'amministratore prima di accettare: da quel momento il proxy si fiderà di questo
                certificato per completare l'enrollment.
              </Alert>
              <div>
                <Text size="xs" c="dimmed">Soggetto</Text>
                <Text size="sm">{certPrompt.subject}</Text>
              </div>
              <div>
                <Text size="xs" c="dimmed">Emittente</Text>
                <Text size="sm">{certPrompt.issuer}</Text>
              </div>
              <div>
                <Text size="xs" c="dimmed">Fingerprint SHA-256</Text>
                <Code style={{ wordBreak: 'break-all' }}>{formatFingerprint(certPrompt.fingerprint)}</Code>
              </div>
              {certPrompt.caFingerprint && (
                <div>
                  <Text size="xs" c="dimmed">CA presentata dal server</Text>
                  <Text size="sm">{certPrompt.caSubject}</Text>
                  <Code style={{ wordBreak: 'break-all' }}>{formatFingerprint(certPrompt.caFingerprint)}</Code>
                </div>
              )}
              <Group justify="flex-end">
                <Button variant="default" onClick={() => setCertPrompt(null)}>Annulla</Button>
                <Button color="orange" onClick={() => requestEnrollment(certPrompt.fingerprint)} loading={busy}>
                  Accetta e continua
                </Button>
              </Group>
            </Stack>
          )}
        </Modal>
      </Stack>
    )
  }

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={3}>Relay</Title>
        <Group gap="xs">
          <Badge color={st.connected ? 'green' : 'red'} variant="light">
            {st.connected ? 'connesso' : 'non connesso'}
          </Badge>
          <Code>{st.address}</Code>
          {st.email && <Badge variant="outline" color="gray">{st.email}</Badge>}
          {st.device && (
            <Group gap={2} wrap="nowrap">
              <Badge variant="outline" color="grape">device {st.device}</Badge>
              <ActionIcon size="sm" variant="subtle" color="grape" title="Rinomina dispositivo"
                onClick={() => { setDeviceValue(st.device); setDeviceOpen(true) }}>
                <IconPencil size={13} />
              </ActionIcon>
            </Group>
          )}
          {st.connected && st.route && <Badge variant="outline" color="gray">via {st.route}</Badge>}
          <Button size="xs" variant="subtle" onClick={() => {
            setEnrollAddress(st.enrollUrl ?? '')
            setEnrollEmail(st.email ?? '')
            setShowEnroll(true)
          }}>Riconfigura</Button>
        </Group>
      </Group>

      {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}
      {st.notice && <Alert color="yellow">{st.notice}</Alert>}
      {!st.connected && st.error && <Alert color="red" title="Connessione al relay">{st.error}</Alert>}

      <Card withBorder>
        <Text fw={700} mb="xs">I miei dispositivi</Text>
        <Text size="xs" c="dimmed" mb="xs">
          I tuoi dispositivi si possono usare direttamente, senza richiesta di contatto:
          l'uscita richiederà comunque l'approvazione della rotta.
        </Text>
        <Table>
          <Table.Tbody>
            {(st.myDevices ?? []).map((d) => (
              <Table.Tr key={d.id}>
                <Table.Td>{d.id}</Table.Td>
                <Table.Td>
                  <Badge size="sm" variant="light" color={d.online ? 'green' : 'gray'}>
                    {d.online ? 'online' : 'offline'}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Code>{st.email ? `relay://${st.email}/${d.id}` : d.id}</Code>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!(st.myDevices ?? []).length && <Text size="sm" c="dimmed">Nessun dispositivo registrato.</Text>}
      </Card>

      {st.approvals.length > 0 && (
        <Card withBorder>
          <Text fw={700} mb="xs">Richieste di rotta da approvare</Text>
          <Text size="xs" c="dimmed" mb="xs">
            Un contatto vuole uscire dalla tua rete verso questa destinazione. Scade dopo 60 secondi.
          </Text>
          <Table>
            <Table.Tbody>
              {st.approvals.map((a) => (
                <Table.Tr key={a.id}>
                  <Table.Td>
                    <Text fw={600}>{a.from}</Text>
                    {a.fromDevice && <Text size="xs" c="dimmed">device {a.fromDevice}</Text>}
                  </Table.Td>
                  <Table.Td><Code>{a.host}:{a.port}</Code></Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end">
                      <Button size="xs" variant="default" onClick={() => run(() => api.relayDecide(a.id, { allow: true }))}>
                        Consenti una volta
                      </Button>
                      <Button size="xs" onClick={() => run(() => api.relayDecide(a.id, { allow: true, always: true }))}>
                        Consenti sempre
                      </Button>
                      <Button size="xs" variant="light" onClick={() => run(() => api.relayDecide(a.id, { allow: true, always: true, anyPort: true }))}>
                        Sempre, tutte le porte
                      </Button>
                      <Button size="xs" color="red" variant="light" onClick={() => run(() => api.relayDecide(a.id, { allow: false }))}>
                        Nega
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}

      {st.incoming.length > 0 && (
        <Card withBorder>
          <Text fw={700} mb="xs">Richieste di contatto</Text>
          <Table>
            <Table.Tbody>
              {st.incoming.map((e) => (
                <Table.Tr key={e}>
                  <Table.Td>{e}</Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end">
                      <Button size="xs" leftSection={<IconCheck size={14} />} onClick={() => run(() => api.relayRespond(e, true))}>
                        Accetta
                      </Button>
                      <Button size="xs" color="red" variant="light" leftSection={<IconX size={14} />} onClick={() => run(() => api.relayRespond(e, false))}>
                        Rifiuta
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}

      <Card withBorder>
        <Group justify="space-between" mb="xs">
          <Text fw={700}>Rubrica</Text>
          <form
            onSubmit={(ev) => {
              ev.preventDefault()
              if (!email.trim()) return
              run(() => api.relayRequest(email.trim())).then(() => setEmail(''))
            }}
          >
            <Group gap="xs">
              <TextInput size="xs" placeholder="indirizzo e-mail del contatto" value={email}
                onChange={(e) => setEmail(e.currentTarget.value)} w={280} />
              <Button size="xs" type="submit" leftSection={<IconPlus size={14} />} disabled={!st.connected}>
                Invia richiesta
              </Button>
            </Group>
          </form>
        </Group>
        <Table>
          <Table.Tbody>
            {st.contacts.map((c) => (
              <Table.Tr key={c.email}>
                <Table.Td>{c.email}</Table.Td>
                <Table.Td><Badge size="sm" variant="light" color={c.online ? 'green' : 'gray'}>{c.online ? 'online' : 'offline'}</Badge></Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    {(c.devices ?? []).map((d) => (
                      <Code key={d}>{`relay://${c.email}/${d}`}</Code>
                    ))}
                    {!(c.devices ?? []).length && c.online && <Code>{`relay://${c.email}`}</Code>}
                    {!c.online && <Text size="sm" c="dimmed">-</Text>}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <ActionIcon variant="subtle" color="red" title="Rimuovi contatto"
                    onClick={() => window.confirm(`Rimuovere ${c.email}?`) && run(() => api.relayRemove(c.email))}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
            {st.outgoing.map((e) => (
              <Table.Tr key={e}>
                <Table.Td>{e}</Table.Td>
                <Table.Td><Badge size="sm" variant="light" color="yellow">in attesa</Badge></Table.Td>
                <Table.Td />
                <Table.Td>
                  <ActionIcon variant="subtle" color="gray" title="Annulla richiesta" onClick={() => run(() => api.relayRemove(e))}>
                    <IconX size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!st.contacts.length && !st.outgoing.length && <Text c="dimmed" size="sm">Nessun contatto</Text>}
        <Text size="xs" c="dimmed" mt="xs">
          Per uscire dalla rete di un contatto usa <Code>relay://email/device</Code> come primo proxy
          della catena di una route. Con un solo device online basta <Code>relay://email</Code>.
          I tuoi dispositivi sono utilizzabili direttamente, senza richiesta di contatto.
        </Text>
      </Card>

      <Card withBorder>
        <Text fw={700} mb="xs">Rotte approvate (chi può uscire dalla tua rete)</Text>
        <Table>
          <Table.Tbody>
            {st.rules.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <Text>{r.from}</Text>
                  {r.fromDevice && <Text size="xs" c="dimmed">device {r.fromDevice}</Text>}
                </Table.Td>
                <Table.Td><Code>{r.host}:{r.port || '*'}</Code></Table.Td>
                <Table.Td>
                  <ActionIcon variant="subtle" color="red" title="Revoca" onClick={() => run(() => api.relayDeleteRule(r.id))}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!st.rules.length && <Text c="dimmed" size="sm">Nessuna rotta approvata</Text>}
      </Card>

      <Modal opened={deviceOpen} onClose={() => setDeviceOpen(false)} title="Nome del dispositivo" centered>
        <Stack gap="sm">
          <Text size="sm" c="dimmed">
            Identifica questo PC agli occhi dei contatti, così possono instradare verso un device
            specifico. Lettere minuscole, numeri, '-' e '_' (max 40 caratteri).
          </Text>
          <TextInput value={deviceValue} placeholder="es. quiet-otter-7f3a"
            onChange={(e) => setDeviceValue(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setDeviceOpen(false)}>Annulla</Button>
            <Button onClick={saveDevice} disabled={!deviceValue.trim()}>Salva</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  )
}
