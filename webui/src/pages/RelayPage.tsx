import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Button, Code, Group, Modal, Stack, Table, Text, Textarea, TextInput,
} from '@mantine/core'
import { IconCheck, IconPencil, IconPlus, IconRouteAltRight, IconTrash, IconUsers, IconX } from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'
import { api, ApiError } from '../api'
import type { CertificatePrompt, RelayStatus } from '../api'
import { Dot, EmptyState, PageHeader, Section } from '../components/ui'
import { ProbeBadge, bestProbe, qualityOf } from '../components/linkQuality'
import type { Probe } from '../components/linkQuality'

const formatFingerprint = (fp: string) =>
  fp.replace(/(..)(?!$)/g, '$1:').toUpperCase()

export default function RelayPage() {
  const { t, i18n } = useTranslation()
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
  const [probes, setProbes] = useState<Record<string, Probe>>({})
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30000)
    return () => clearInterval(timer)
  }, [])
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

  // --- link quality -------------------------------------------------------
  // Every path worth knowing about: the relay itself, the online devices of
  // each contact and our other devices. Probing crosses the real path
  // (this computer -> relay -> contact's computer and back) without opening
  // anything on the other side.
  const targets = useMemo(() => {
    if (!st?.connected) return [] as { email: string; device: string }[]
    const out = [{ email: '', device: '' }]
    for (const c of st.contacts) {
      if (!c.online) continue
      if (c.devices?.length) c.devices.forEach((d) => out.push({ email: c.email, device: d }))
      else out.push({ email: c.email, device: '' })
    }
    for (const d of st.myDevices ?? []) {
      if (d.online && d.id !== st.device) out.push({ email: st.email, device: d.id })
    }
    return out
  }, [st])
  const targetsKey = JSON.stringify(targets)
  const probe = useCallback(async (email: string, device: string) => {
    const key = `${email}|${device}`
    setProbes((p) => ({ ...p, [key]: { state: 'pending' } }))
    try {
      const r = await api.relayPing(email, device)
      setProbes((p) => ({ ...p, [key]: { state: 'done', ok: r.ok, rttMs: r.rttMs, error: r.error, at: Date.now() } }))
    } catch (e) {
      setProbes((p) => ({ ...p, [key]: { state: 'done', ok: false, error: String(e), at: Date.now() } }))
    }
  }, [])
  const probeAll = useCallback(async () => {
    const list: { email: string; device: string }[] = JSON.parse(targetsKey)
    for (let i = 0; i < list.length; i += 3) {
      await Promise.all(list.slice(i, i + 3).map((x) => probe(x.email, x.device)))
    }
  }, [targetsKey, probe])
  useEffect(() => {
    if (targetsKey === '[]') return
    probeAll()
    const timer = setInterval(probeAll, 60000)
    return () => clearInterval(timer)
  }, [targetsKey, probeAll])
  const probeOf = (email: string, device: string) => probes[`${email}|${device}`]
  const ago = (unixSeconds: number) => {
    const rtf = new Intl.RelativeTimeFormat(i18n.language, { numeric: 'auto' })
    const secs = Math.max(0, Math.floor(now / 1000 - unixSeconds))
    if (secs < 60) return rtf.format(0, 'second')
    if (secs < 3600) return rtf.format(-Math.floor(secs / 60), 'minute')
    if (secs < 86400) return rtf.format(-Math.floor(secs / 3600), 'hour')
    return rtf.format(-Math.floor(secs / 86400), 'day')
  }

  if (!st) return null
  if (!st.enabled || showEnroll) {
    return (
      <Stack gap={0}>
        <PageHeader icon={IconRouteAltRight} title={t('Relay')}
          description={t('Reach services through the network of your contacts, and let them reach yours, over an authenticated mTLS channel.')} />
        {error && <Alert color="red" withCloseButton onClose={() => setError(null)} mb="md">{error}</Alert>}
        {enrollPhase === 'form' ? (
          <Section
            title={t('Connect this device to the relay')}
            description={t('Enter the enrollment endpoint address and your email. The relay will send a confirmation code; the certificate will be created locally and signed by the relay.')}
          >
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
          </Section>
        ) : (
          <Section
            title={t('Code sent to {{email}}', { email: enrollEmail })}
            description={t('Check your email and enter the confirmation code here. The code expires after 15 minutes.')}
          >
            <Group gap="xs" align="flex-end">
              <TextInput label={t('Code')} placeholder="ABCD-EFGH" value={enrollCode}
                onChange={(e) => setEnrollCode(e.currentTarget.value)}
                onKeyDown={(e) => e.key === 'Enter' && enrollCode.trim() && confirmEnrollment()} />
              <Button onClick={confirmEnrollment} loading={busy} disabled={!enrollCode.trim()}>{t('Confirm')}</Button>
              <Button variant="subtle" onClick={() => setEnrollPhase('form')}>{t('Back')}</Button>
            </Group>
          </Section>
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
    <Stack gap={0}>
      <PageHeader
        icon={IconRouteAltRight}
        title={t('Relay')}
        description={
          <Group gap="xs">
            <Badge color={st.connected ? 'green' : 'red'} variant="dot" size="lg" tt="none">
              {st.connected ? t('connected') : t('not connected')}
            </Badge>
            <Code>{st.address}</Code>
            {st.email && <Badge variant="outline" color="gray" tt="none">{st.email}</Badge>}
            {st.device && (
              <Group gap={2} wrap="nowrap">
                <Badge variant="outline" color="grape" tt="none">{t('device {{id}}', { id: st.device })}</Badge>
                <ActionIcon size="sm" variant="subtle" color="grape" title={t('Rename device')} aria-label={t('Rename device')}
                  onClick={() => { setDeviceValue(st.device); setDeviceOpen(true) }}>
                  <IconPencil size={13} />
                </ActionIcon>
              </Group>
            )}
            {st.connected && st.route && <Badge variant="outline" color="gray" tt="none">{t('via {{route}}', { route: st.route })}</Badge>}
            {st.connected && (
              <Group gap={4} wrap="nowrap">
                <Text size="xs" c="dimmed">{t('relay latency')}</Text>
                <ProbeBadge probe={probeOf('', '')} onTest={() => probe('', '')} />
              </Group>
            )}
          </Group>
        }
        actions={
          <>
            <Button variant="default" disabled={!st.connected} onClick={() => probeAll()}>{t('Test connections')}</Button>
          <Button variant="default" onClick={() => {
            setEnrollAddress(st.enrollUrl ?? '')
            setEnrollEmail(st.email ?? '')
            setShowEnroll(true)
          }}>{t('Reconfigure')}</Button>
          </>
        }
      />

      {error && <Alert color="red" withCloseButton onClose={() => setError(null)} mb="md">{error}</Alert>}
      {st.notice && <Alert color="yellow" mb="md">{st.notice}</Alert>}
      {!st.connected && st.error && <Alert color="red" title={t('Relay connection')} mb="md">{st.error}</Alert>}

      {st.incoming.length > 0 && (
        <Section accent="yellow" title={t('Contact requests')}
          description={t('A user wants to add you to their address book. Accept or decline to clear the request.')}
          right={<Badge color="yellow">{st.incoming.length}</Badge>}>
          <Table.ScrollContainer minWidth={420}>
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
          </Table.ScrollContainer>
        </Section>
      )}

      <Section title={t('My devices')}
        description={t('Your devices can be used directly, without a contact request; outbound traffic will still require route approval.')}>
        <Table.ScrollContainer minWidth={420}>
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
                <Table.Td>
                  {d.id === st.device
                    ? <Text size="xs" c="dimmed">{t('this computer')}</Text>
                    : d.online && <ProbeBadge probe={probeOf(st.email, d.id)} onTest={() => probe(st.email, d.id)} />}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        </Table.ScrollContainer>
        {!(st.myDevices ?? []).length && <EmptyState icon={IconRouteAltRight} title={t('No registered devices.')} />}
      </Section>

      {st.approvals.length > 0 && (
        <Section accent="orange" title={t('Route requests to approve')}
          description={t('A contact wants to exit your network toward this destination. Expires after 60 seconds.')}>
          <Table.ScrollContainer minWidth={640}>
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
          </Table.ScrollContainer>
        </Section>
      )}

      <Section title={t('Contacts')} right={
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
        }>
        <Table.ScrollContainer minWidth={760}>
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('Contact')}</Table.Th>
              <Table.Th>{t('Status')}</Table.Th>
              <Table.Th>{t('Is it worth it?')}</Table.Th>
              <Table.Th>{t('Devices and latency')}</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {st.contacts.map((c) => {
              const paths = c.devices?.length ? c.devices : ['']
              const best = c.online ? bestProbe(paths.map((d) => probeOf(c.email, d))) : null
              const tested = paths.every((d) => probeOf(c.email, d)?.state === 'done')
              return (
              <Table.Tr key={c.email}>
                <Table.Td><Text fw={600} size="sm">{c.email}</Text></Table.Td>
                <Table.Td>
                  <Group gap={6} wrap="nowrap">
                    <Dot color={c.online ? 'green' : 'gray'} />
                    <Text size="sm">{c.online ? t('online') : t('offline')}</Text>
                  </Group>
                  {!c.online && (
                    <Text size="xs" c="dimmed">
                      {c.lastSeen ? t('last seen {{when}}', { when: ago(c.lastSeen) }) : t('never seen online')}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  {!c.online && <Badge size="sm" variant="light" color="gray" tt="none">{t('not available')}</Badge>}
                  {c.online && best && (
                    <Badge size="sm" variant="filled" tt="none"
                      color={qualityOf(best.rttMs) === 'good' ? 'green' : qualityOf(best.rttMs) === 'ok' ? 'yellow' : 'orange'}>
                      {qualityOf(best.rttMs) === 'good' ? t('worth using') : qualityOf(best.rttMs) === 'ok' ? t('usable') : t('slow')}
                    </Badge>
                  )}
                  {c.online && !best && tested && <Badge size="sm" variant="light" color="red" tt="none">{t('online, not reachable')}</Badge>}
                  {c.online && !best && !tested && <Text size="xs" c="dimmed">{t('testing...')}</Text>}
                </Table.Td>
                <Table.Td>
                  <Stack gap={4}>
                    {c.online && paths.map((d) => (
                      <Group key={d || 'any'} gap="xs" wrap="nowrap">
                        <Code>{d ? `relay://${c.email}/${d}` : `relay://${c.email}`}</Code>
                        <ProbeBadge probe={probeOf(c.email, d)} onTest={() => probe(c.email, d)} />
                      </Group>
                    ))}
                    {!c.online && <Text size="sm" c="dimmed">-</Text>}
                  </Stack>
                </Table.Td>
                <Table.Td>
                  <ActionIcon variant="subtle" color="red" title={t('Remove contact')}
                    onClick={() => window.confirm(t('Remove {{email}}?', { email: c.email })) && run(() => api.relayRemove(c.email))}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
              )
            })}
            {st.outgoing.map((e) => (
              <Table.Tr key={e}>
                <Table.Td>{e}</Table.Td>
                <Table.Td><Badge size="sm" variant="light" color="yellow">{t('pending')}</Badge></Table.Td>
                <Table.Td />
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
        </Table.ScrollContainer>
        {!st.contacts.length && !st.outgoing.length && (
          <EmptyState icon={IconUsers} title={t('No contacts')}
            text={t('Send a request to a colleague to route traffic through each other\'s networks.')} />
        )}
        <Text size="xs" c="dimmed" mt="xs">
          {t('Latency is measured end to end (this computer, the relay, the contact\'s computer and back) every minute while this page is open, without opening anything on the other side. "Worth using" means below 150 ms; "usable" below 400 ms.')}
        </Text>
        <Text size="xs" c="dimmed" mt="xs">
          {t("To exit a contact's network, use")} <Code>relay://email/device</Code>{' '}
          {t('as the first proxy in a route chain. With only one device online,')} <Code>relay://email</Code>{' '}
          {t('is enough. Your devices can be used directly, without a contact request.')}
        </Text>
      </Section>

      <Section title={t('Approved routes (who can exit your network)')}>
        <Table.ScrollContainer minWidth={420}>
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
        </Table.ScrollContainer>
        {!st.rules.length && <EmptyState icon={IconRouteAltRight} title={t('No approved routes')} />}
      </Section>

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
