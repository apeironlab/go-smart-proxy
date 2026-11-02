import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Button, Card, Code, Group, Modal, Stack, Table, Text, Textarea, TextInput, Title,
} from '@mantine/core'
import { IconCheck, IconPencil, IconPlus, IconTrash, IconX } from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'
import { api, ApiError } from '../api'
import type { CertificatePrompt, RelayStatus } from '../api'

const formatFingerprint = (fp: string) =>
  fp.replace(/(..)(?!$)/g, '$1:').toUpperCase()

export default function RelayPage() {
  const { t } = useTranslation()
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
        <Title order={3}>{t('Relay')}</Title>
        {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}
        {enrollPhase === 'form' ? (
          <Card withBorder>
            <Text fw={700} mb="xs">{t('Connect this device to the relay')}</Text>
            <Text size="sm" c="dimmed" mb="sm">
              {t('Enter the enrollment endpoint address and your email. The relay will send a confirmation code; the certificate will be created locally and signed by the relay.')}
            </Text>
            <Stack gap="sm">
              <TextInput label={t('Relay address (enrollment)')} placeholder="relay.example.com:8444"
                value={enrollAddress} onChange={(e) => setEnrollAddress(e.currentTarget.value)} />
              <TextInput label={t('Email')} placeholder="nome@dominio.it"
                value={enrollEmail} onChange={(e) => setEnrollEmail(e.currentTarget.value)} />
              <Textarea label={t('CA for the enrollment endpoint (optional, PEM)')}
                description={t('Only needed if the HTTPS enrollment endpoint uses an internal CA. The mTLS relay CA is provided by the relay.')}
                minRows={3} value={enrollCA} onChange={(e) => setEnrollCA(e.currentTarget.value)} />
              <Group justify="flex-end">
                {st.enabled && <Button variant="subtle" onClick={() => setShowEnroll(false)}>{t('Cancel')}</Button>}
                <Button onClick={() => requestEnrollment()} loading={busy}
                  disabled={!enrollAddress.trim() || !enrollEmail.trim()}>
                  {t('Send request')}
                </Button>
              </Group>
            </Stack>
          </Card>
        ) : (
          <Card withBorder>
            <Text fw={700} mb="xs">{t('Code sent to {{email}}', { email: enrollEmail })}</Text>
            <Text size="sm" c="dimmed" mb="sm">
              {t('Check your email and enter the confirmation code here. The code expires after 15 minutes.')}
            </Text>
            <Group gap="xs" align="flex-end">
              <TextInput label={t('Code')} placeholder="ABCD-EFGH" value={enrollCode}
                onChange={(e) => setEnrollCode(e.currentTarget.value)}
                onKeyDown={(e) => e.key === 'Enter' && enrollCode.trim() && confirmEnrollment()} />
              <Button onClick={confirmEnrollment} loading={busy} disabled={!enrollCode.trim()}>{t('Confirm')}</Button>
              <Button variant="subtle" onClick={() => setEnrollPhase('form')}>{t('Back')}</Button>
            </Group>
          </Card>
        )}

        <Modal opened={!!certPrompt} onClose={() => setCertPrompt(null)}
          title={t('Unrecognized certificate')} centered size="lg">
          {certPrompt && (
            <Stack gap="sm">
              <Alert color="yellow">
                {t('The CA for this certificate is unknown. Verify the fingerprint with the administrator before accepting: from that point on, the proxy will trust this certificate to complete the enrollment.')}
              </Alert>
              <div>
                <Text size="xs" c="dimmed">{t('Subject')}</Text>
                <Text size="sm">{certPrompt.subject}</Text>
              </div>
              <div>
                <Text size="xs" c="dimmed">{t('Issuer')}</Text>
                <Text size="sm">{certPrompt.issuer}</Text>
              </div>
              <div>
                <Text size="xs" c="dimmed">{t('SHA-256 fingerprint')}</Text>
                <Code style={{ wordBreak: 'break-all' }}>{formatFingerprint(certPrompt.fingerprint)}</Code>
              </div>
              {certPrompt.caFingerprint && (
                <div>
                  <Text size="xs" c="dimmed">{t('CA presented by the server')}</Text>
                  <Text size="sm">{certPrompt.caSubject}</Text>
                  <Code style={{ wordBreak: 'break-all' }}>{formatFingerprint(certPrompt.caFingerprint)}</Code>
                </div>
              )}
              <Group justify="flex-end">
                <Button variant="default" onClick={() => setCertPrompt(null)}>{t('Cancel')}</Button>
                <Button color="orange" onClick={() => requestEnrollment(certPrompt.fingerprint)} loading={busy}>
                  {t('Accept and continue')}
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
        <Title order={3}>{t('Relay')}</Title>
        <Group gap="xs">
          <Badge color={st.connected ? 'green' : 'red'} variant="light">
            {st.connected ? t('connected') : t('not connected')}
          </Badge>
          <Code>{st.address}</Code>
          {st.email && <Badge variant="outline" color="gray">{st.email}</Badge>}
          {st.device && (
            <Group gap={2} wrap="nowrap">
              <Badge variant="outline" color="grape">{t('device {{id}}', { id: st.device })}</Badge>
              <ActionIcon size="sm" variant="subtle" color="grape" title={t('Rename device')}
                onClick={() => { setDeviceValue(st.device); setDeviceOpen(true) }}>
                <IconPencil size={13} />
              </ActionIcon>
            </Group>
          )}
          {st.connected && st.route && <Badge variant="outline" color="gray">{t('via {{route}}', { route: st.route })}</Badge>}
          <Button size="xs" variant="subtle" onClick={() => {
            setEnrollAddress(st.enrollUrl ?? '')
            setEnrollEmail(st.email ?? '')
            setShowEnroll(true)
          }}>{t('Reconfigure')}</Button>
        </Group>
      </Group>

      {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}
      {st.notice && <Alert color="yellow">{st.notice}</Alert>}
      {!st.connected && st.error && <Alert color="red" title={t('Relay connection')}>{st.error}</Alert>}

      {st.incoming.length > 0 && (
        <Card withBorder style={{ borderColor: 'var(--mantine-color-yellow-6)' }}>
          <Group justify="space-between" mb="xs">
            <Text fw={700}>{t('Contact requests')}</Text>
            <Badge color="yellow">{st.incoming.length}</Badge>
          </Group>
          <Text size="xs" c="dimmed" mb="xs">
            {t('A user wants to add you to their address book. Accept or decline to clear the request.')}
          </Text>
          <Table>
            <Table.Tbody>
              {st.incoming.map((e) => (
                <Table.Tr key={e}>
                  <Table.Td>{e}</Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end">
                      <Button size="xs" leftSection={<IconCheck size={14} />} onClick={() => run(() => api.relayRespond(e, true))}>
                        {t('Accept')}
                      </Button>
                      <Button size="xs" color="red" variant="light" leftSection={<IconX size={14} />} onClick={() => run(() => api.relayRespond(e, false))}>
                        {t('Decline')}
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
        <Text fw={700} mb="xs">{t('My devices')}</Text>
        <Text size="xs" c="dimmed" mb="xs">
          {t('Your devices can be used directly, without a contact request; outbound traffic will still require route approval.')}
        </Text>
        <Table>
          <Table.Tbody>
            {(st.myDevices ?? []).map((d) => (
              <Table.Tr key={d.id}>
                <Table.Td>{d.id}</Table.Td>
                <Table.Td>
                  <Badge size="sm" variant="light" color={d.online ? 'green' : 'gray'}>
                    {d.online ? t('online') : t('offline')}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Code>{st.email ? `relay://${st.email}/${d.id}` : d.id}</Code>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!(st.myDevices ?? []).length && <Text size="sm" c="dimmed">{t('No registered devices.')}</Text>}
      </Card>

      {st.approvals.length > 0 && (
        <Card withBorder>
          <Text fw={700} mb="xs">{t('Route requests to approve')}</Text>
          <Text size="xs" c="dimmed" mb="xs">
            {t('A contact wants to exit your network toward this destination. Expires after 60 seconds.')}
          </Text>
          <Table>
            <Table.Tbody>
              {st.approvals.map((a) => (
                <Table.Tr key={a.id}>
                  <Table.Td>
                    <Text fw={600}>{a.from}</Text>
                    {a.fromDevice && <Text size="xs" c="dimmed">{t('device {{id}}', { id: a.fromDevice })}</Text>}
                  </Table.Td>
                  <Table.Td><Code>{a.host}:{a.port}</Code></Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end">
                      <Button size="xs" variant="default" onClick={() => run(() => api.relayDecide(a.id, { allow: true }))}>
                        {t('Allow once')}
                      </Button>
                      <Button size="xs" onClick={() => run(() => api.relayDecide(a.id, { allow: true, always: true }))}>
                        {t('Always allow')}
                      </Button>
                      <Button size="xs" variant="light" onClick={() => run(() => api.relayDecide(a.id, { allow: true, always: true, anyPort: true }))}>
                        {t('Always, all ports')}
                      </Button>
                      <Button size="xs" color="red" variant="light" onClick={() => run(() => api.relayDecide(a.id, { allow: false }))}>
                        {t('Deny')}
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
          <Text fw={700}>{t('Contacts')}</Text>
          <form
            onSubmit={(ev) => {
              ev.preventDefault()
              if (!email.trim()) return
              run(() => api.relayRequest(email.trim())).then(() => setEmail(''))
            }}
          >
            <Group gap="xs">
              <TextInput size="xs" placeholder={t('contact email address')} value={email}
                onChange={(e) => setEmail(e.currentTarget.value)} w={280} />
              <Button size="xs" type="submit" leftSection={<IconPlus size={14} />} disabled={!st.connected}>
                {t('Send request')}
              </Button>
            </Group>
          </form>
        </Group>
        <Table>
          <Table.Tbody>
            {st.contacts.map((c) => (
              <Table.Tr key={c.email}>
                <Table.Td>{c.email}</Table.Td>
                <Table.Td><Badge size="sm" variant="light" color={c.online ? 'green' : 'gray'}>{c.online ? t('online') : t('offline')}</Badge></Table.Td>
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
                  <ActionIcon variant="subtle" color="red" title={t('Remove contact')}
                    onClick={() => window.confirm(t('Remove {{email}}?', { email: c.email })) && run(() => api.relayRemove(c.email))}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
            {st.outgoing.map((e) => (
              <Table.Tr key={e}>
                <Table.Td>{e}</Table.Td>
                <Table.Td><Badge size="sm" variant="light" color="yellow">{t('pending')}</Badge></Table.Td>
                <Table.Td />
                <Table.Td>
                  <ActionIcon variant="subtle" color="gray" title={t('Cancel request')} onClick={() => run(() => api.relayRemove(e))}>
                    <IconX size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!st.contacts.length && !st.outgoing.length && <Text c="dimmed" size="sm">{t('No contacts')}</Text>}
        <Text size="xs" c="dimmed" mt="xs">
          {t("To exit a contact's network, use")} <Code>relay://email/device</Code>{' '}
          {t('as the first proxy in a route chain. With only one device online,')} <Code>relay://email</Code>{' '}
          {t('is enough. Your devices can be used directly, without a contact request.')}
        </Text>
      </Card>

      <Card withBorder>
        <Text fw={700} mb="xs">{t('Approved routes (who can exit your network)')}</Text>
        <Table>
          <Table.Tbody>
            {st.rules.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <Text>{r.from}</Text>
                  {r.fromDevice && <Text size="xs" c="dimmed">{t('device {{id}}', { id: r.fromDevice })}</Text>}
                </Table.Td>
                <Table.Td><Code>{r.host}:{r.port || '*'}</Code></Table.Td>
                <Table.Td>
                  <ActionIcon variant="subtle" color="red" title={t('Revoke')} onClick={() => run(() => api.relayDeleteRule(r.id))}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!st.rules.length && <Text c="dimmed" size="sm">{t('No approved routes')}</Text>}
      </Card>

      <Modal opened={deviceOpen} onClose={() => setDeviceOpen(false)} title={t('Device name')} centered>
        <Stack gap="sm">
          <Text size="sm" c="dimmed">
            {t("Identify this PC to your contacts so they can route to a specific device. Lowercase letters, numbers, '-' and '_' (max 40 characters).")}
          </Text>
          <TextInput value={deviceValue} placeholder={t('e.g. quiet-otter-7f3a')}
            onChange={(e) => setDeviceValue(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setDeviceOpen(false)}>{t('Cancel')}</Button>
            <Button onClick={saveDevice} disabled={!deviceValue.trim()}>{t('Save')}</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  )
}
