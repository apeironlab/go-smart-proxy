import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ActionIcon, Alert, Badge, Button, Code, CopyButton, Group, Modal, SegmentedControl, Select, Stack, Switch, Table, TagsInput,
  Text, Textarea, TextInput, Tooltip,
} from '@mantine/core'
import { IconApps, IconCheck, IconCopy, IconDownload, IconKey, IconPencil, IconPlus, IconServer2, IconTrash } from '@tabler/icons-react'
import { Dot, EmptyState, PageHeader, Section } from '../../src/components/ui'
import { adminApi } from '../api'
import type { AppDef, GatewayInfo, GatewayIssued } from '../api'
import { fmtDate } from '../format'
import { message, usePolling } from '../hooks'

export default function AppsPage() {
  const { t } = useTranslation()
  const catalog = usePolling(adminApi.apps, 0)
  const gateways = usePolling(adminApi.gateways, 5000)
  const [problem, setProblem] = useState<string | null>(null)
  const [editing, setEditing] = useState<AppDef | 'new' | null>(null)
  const [issued, setIssued] = useState<GatewayIssued | null>(null)
  const [newGateway, setNewGateway] = useState(false)

  const apps = catalog.data?.apps ?? []
  const readOnly = !!catalog.data?.readOnly

  const saveAll = async (next: AppDef[]) => {
    try {
      await adminApi.saveApps(next)
      setProblem(null)
      catalog.reload()
      gateways.reload()
      return true
    } catch (e) {
      setProblem(message(e))
      return false
    }
  }

  return (
    <>
      <PageHeader
        icon={IconApps} title={t('Applications')}
        description={t('Applications users open through their proxy. The relay tells each person only the applications they may open; where an application is stays here and on its gateway.')}
        actions={catalog.data?.enabled && !readOnly ? <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')}>{t('Add application')}</Button> : undefined}
      />
      {(problem || catalog.error) && <Alert color="red" variant="light" mb="md">{problem ?? catalog.error}</Alert>}
      {catalog.data && !catalog.data.enabled && (
        <Alert color="yellow" variant="light" mb="md">{t('This relay does not serve applications: it was started without a catalog.')}</Alert>
      )}
      {readOnly && <Alert color="blue" variant="light" mb="md">{t('The catalog is read from a file on the relay. Edit that file to change it.')}</Alert>}

      {catalog.data?.enabled && (
        <Section>
          {apps.length === 0 ? (
            <EmptyState icon={IconApps} title={t('No applications')} text={t('Add the first one: pick a host name, a gateway and who may open it.')} />
          ) : (
            <Table.ScrollContainer minWidth={760}>
              <Table highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('Application')}</Table.Th>
                    <Table.Th>{t('Host name')}</Table.Th>
                    <Table.Th>{t('Gateway')}</Table.Th>
                    <Table.Th>{t('Who')}</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {apps.map((a) => {
                    const gw = gateways.data?.find((g) => g.id === a.gateway)
                    return (
                      <Table.Tr key={a.id} opacity={a.disabled ? 0.55 : 1}>
                        <Table.Td>
                          <Group gap={6} wrap="nowrap"><Text size="sm" fw={600}>{a.name}</Text>
                            <Badge variant="light" tt="none" size="sm">{a.kind === 'http' ? 'http' : 'tcp'}</Badge>
                            {a.disabled && <Badge color="gray" variant="light" size="sm">{t('off')}</Badge>}
                          </Group>
                          {a.description && <Text size="xs" c="dimmed">{a.description}</Text>}
                        </Table.Td>
                        <Table.Td><Text size="sm" ff="monospace">{a.host}</Text></Table.Td>
                        <Table.Td><Group gap={6} wrap="nowrap"><Dot color={gw?.online ? 'green' : 'gray'} /><Text size="sm">{a.gateway}</Text></Group></Table.Td>
                        <Table.Td>
                          <Group gap={4}>
                            {a.everyone && <Badge variant="light" color="teal" tt="none">{t('everybody')}</Badge>}
                            {(a.groups ?? []).map((g) => <Badge key={'g' + g} variant="light" tt="none">{g}</Badge>)}
                            {(a.emails ?? []).map((e) => <Badge key={'e' + e} variant="outline" color="gray" tt="none">{e}</Badge>)}
                            {!a.everyone && !(a.groups ?? []).length && !(a.emails ?? []).length && <Text size="xs" c="red">{t('nobody')}</Text>}
                          </Group>
                        </Table.Td>
                        <Table.Td>
                          {!readOnly && (
                            <Group gap={4} justify="flex-end" wrap="nowrap">
                              <Tooltip label={t('Edit')}>
                                <ActionIcon variant="subtle" aria-label={t('Edit')} onClick={() => setEditing(a)}><IconPencil size={16} /></ActionIcon>
                              </Tooltip>
                              <Tooltip label={t('Delete')}>
                                <ActionIcon
                                  variant="subtle" color="red" aria-label={t('Delete')}
                                  onClick={() => { if (window.confirm(t('Delete the application {{name}}?', { name: a.name }))) void saveAll(apps.filter((x) => x.id !== a.id)) }}
                                ><IconTrash size={16} /></ActionIcon>
                              </Tooltip>
                            </Group>
                          )}
                        </Table.Td>
                      </Table.Tr>
                    )
                  })}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Section>
      )}

      <Section
        title={t('Gateways')}
        description={t('A gateway is a small program installed next to the application. It connects out to this relay with its own certificate, receives the applications it serves and reaches only those.')}
        right={<Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setNewGateway(true)}>{t('New gateway')}</Button>}
      >
        {(gateways.data ?? []).length === 0 ? (
          <EmptyState icon={IconServer2} title={t('No gateways yet')} />
        ) : (
          <Table.ScrollContainer minWidth={620}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('Gateway')}</Table.Th>
                  <Table.Th>{t('Applications')}</Table.Th>
                  <Table.Th>{t('Certificate')}</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {(gateways.data ?? []).map((g: GatewayInfo) => {
                  const live = g.certs.filter((c) => !c.revoked && new Date(c.expires).getTime() > Date.now())
                  return (
                    <Table.Tr key={g.id}>
                      <Table.Td><Group gap={6} wrap="nowrap"><Dot color={g.online ? 'green' : 'gray'} /><Text size="sm" fw={600}>{g.id}</Text>
                        <Text size="xs" c="dimmed">{g.online ? t('connected') : t('not connected')}</Text></Group></Table.Td>
                      <Table.Td>{g.apps}</Table.Td>
                      <Table.Td>
                        {live.length > 0
                          ? <Text size="sm">{t('valid until {{date}}', { date: fmtDate(live[0].expires) })}</Text>
                          : <Text size="sm" c="dimmed">{g.certs.length ? t('revoked or expired') : t('none issued here')}</Text>}
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4} justify="flex-end" wrap="nowrap">
                          <Tooltip label={t('Issue a new certificate')}>
                            <ActionIcon variant="subtle" aria-label={t('Issue a new certificate')} onClick={() => {
                              void adminApi.issueGateway(g.id).then((x) => { setIssued(x); gateways.reload() }).catch((e: unknown) => setProblem(message(e)))
                            }}><IconKey size={16} /></ActionIcon>
                          </Tooltip>
                          {live.length > 0 && (
                            <Tooltip label={t('Revoke its certificates and disconnect it')}>
                              <ActionIcon variant="subtle" color="red" aria-label={t('Revoke')} onClick={() => {
                                if (window.confirm(t('Revoke every certificate of the gateway {{id}}?', { id: g.id }))) {
                                  void adminApi.revokeGateway(g.id).then(gateways.reload).catch((e: unknown) => setProblem(message(e)))
                                }
                              }}><IconTrash size={16} /></ActionIcon>
                            </Tooltip>
                          )}
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  )
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Section>

      {editing && (
        <AppModal
          app={editing === 'new' ? null : editing}
          gateways={(gateways.data ?? []).map((g) => g.id)}
          taken={apps.map((a) => a.id)}
          onClose={() => setEditing(null)}
          onSave={async (a) => {
            const next = editing === 'new' ? [...apps, a] : apps.map((x) => (x.id === a.id ? a : x))
            if (await saveAll(next)) setEditing(null)
          }}
        />
      )}
      {newGateway && (
        <NewGatewayModal
          onClose={() => setNewGateway(false)}
          onIssued={(x) => { setNewGateway(false); setIssued(x); gateways.reload() }}
        />
      )}
      {issued && <IssuedModal issued={issued} onClose={() => setIssued(null)} />}
    </>
  )
}

function headersToText(h?: Record<string, string>) {
  return Object.entries(h ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')
}

function textToHeaders(s: string): Record<string, string> | undefined {
  const out: Record<string, string> = {}
  for (const line of s.split('\n')) {
    const i = line.indexOf(':')
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return Object.keys(out).length ? out : undefined
}

function AppModal({ app, gateways, taken, onClose, onSave }: {
  app: AppDef | null
  gateways: string[]
  taken: string[]
  onClose: () => void
  onSave: (a: AppDef) => Promise<void>
}) {
  const { t } = useTranslation()
  const [id, setId] = useState(app?.id ?? '')
  const [name, setName] = useState(app?.name ?? '')
  const [description, setDescription] = useState(app?.description ?? '')
  const [host, setHost] = useState(app?.host ?? '')
  const [kind, setKind] = useState<'tcp' | 'http'>(app?.kind ?? 'http')
  const [gateway, setGateway] = useState(app?.gateway ?? gateways[0] ?? '')
  const [target, setTarget] = useState(app?.target ?? '')
  const [everyone, setEveryone] = useState(app?.everyone ?? false)
  const [groups, setGroups] = useState<string[]>(app?.groups ?? [])
  const [emails, setEmails] = useState<string[]>(app?.emails ?? [])
  const [headers, setHeaders] = useState(headersToText(app?.setHeaders))
  const [disabled, setDisabled] = useState(app?.disabled ?? false)
  const [busy, setBusy] = useState(false)

  const idClash = !app && taken.includes(id)
  const submit = async () => {
    setBusy(true)
    await onSave({
      id: id.trim(), name: name.trim(), description: description.trim() || undefined, host: host.trim().toLowerCase(), kind,
      gateway: gateway.trim(), target: target.trim(), everyone: everyone || undefined, groups: groups.length ? groups : undefined,
      emails: emails.length ? emails : undefined, setHeaders: kind === 'http' ? textToHeaders(headers) : undefined, disabled: disabled || undefined,
    })
    setBusy(false)
  }

  return (
    <Modal opened onClose={onClose} title={app ? t('Edit {{name}}', { name: app.name }) : t('Add application')} size="lg">
      <form onSubmit={(e) => { e.preventDefault(); void submit() }}>
        <Stack gap="sm">
          <Group grow align="flex-start">
            <TextInput label={t('Name')} value={name} onChange={(e) => setName(e.currentTarget.value)} required autoFocus />
            <TextInput
              label={t('Identifier')} description={t('Lowercase letters, digits, - and _')} value={id} onChange={(e) => setId(e.currentTarget.value)}
              disabled={!!app} required error={idClash ? t('Already in use') : undefined}
            />
          </Group>
          <TextInput label={t('Description')} value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
          <TextInput
            label={t('Host name')} placeholder="crm.apps.example.com" required
            description={t('What users type. It does not need to exist in DNS: the proxy sends it to the relay.')}
            value={host} onChange={(e) => setHost(e.currentTarget.value)}
          />
          <SegmentedControl
            value={kind} onChange={(v) => setKind(v as 'tcp' | 'http')}
            data={[{ value: 'http', label: t('Web (reverse proxy)') }, { value: 'tcp', label: t('Network service (TCP)') }]}
          />
          <Group grow align="flex-start">
            <Select
              label={t('Gateway')} data={gateways} value={gateway || null} onChange={(v) => setGateway(v ?? '')} searchable required
              nothingFoundMessage={t('Create the gateway below first')}
            />
            <TextInput
              label={kind === 'http' ? t('Backend URL') : t('Backend address')} required value={target} onChange={(e) => setTarget(e.currentTarget.value)}
              placeholder={kind === 'http' ? 'https://crm.internal:8443' : '10.0.0.5:3389'}
              description={t('Only the gateway sees this.')}
            />
          </Group>
          <Switch checked={everyone} onChange={(e) => setEveryone(e.currentTarget.checked)} label={t('Open to everybody who is signed in to this relay')} />
          {!everyone && (
            <>
              <TagsInput
                label={t('Groups')} value={groups} onChange={setGroups}
                description={t('Groups come from the identity provider at sign-in (password, LDAP, OpenID Connect, SAML), and are as recent as the user\'s last enrollment.')}
              />
              <TagsInput label={t('E-mail addresses')} value={emails} onChange={setEmails} />
              {!groups.length && !emails.length && <Text size="xs" c="red">{t('With no group and no address, nobody can open it.')}</Text>}
            </>
          )}
          {kind === 'http' && (
            <Textarea
              label={t('Headers added to every request')} value={headers} onChange={(e) => setHeaders(e.currentTarget.value)} minRows={2} autosize
              description={t('One per line, as Name: value. For instance an identity header the application trusts.')}
            />
          )}
          <Switch checked={disabled} onChange={(e) => setDisabled(e.currentTarget.checked)} label={t('Switched off')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>{t('Cancel')}</Button>
            <Button type="submit" loading={busy} disabled={idClash}>{t('Save')}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}

function NewGatewayModal({ onClose, onIssued }: { onClose: () => void; onIssued: (x: GatewayIssued) => void }) {
  const { t } = useTranslation()
  const [id, setId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  return (
    <Modal opened onClose={onClose} title={t('New gateway')}>
      <form onSubmit={(e) => {
        e.preventDefault()
        setBusy(true)
        adminApi.issueGateway(id.trim()).then(onIssued).catch((x: unknown) => { setError(message(x)); setBusy(false) })
      }}>
        <Stack gap="sm">
          {error && <Alert color="red" variant="light">{error}</Alert>}
          <TextInput
            label={t('Identifier')} description={t('Lowercase letters, digits, - and _. Applications name it as their gateway.')}
            value={id} onChange={(e) => setId(e.currentTarget.value)} required autoFocus
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>{t('Cancel')}</Button>
            <Button type="submit" loading={busy}>{t('Issue the certificate')}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

function IssuedModal({ issued, onClose }: { issued: GatewayIssued; onClose: () => void }) {
  const { t } = useTranslation()
  const files = [
    { name: 'gateway.pem', text: issued.certPem },
    { name: 'gateway-key.pem', text: issued.keyPem },
    { name: 'ca.pem', text: issued.caPem },
  ]
  return (
    <Modal opened onClose={onClose} title={t('Certificate of the gateway {{id}}', { id: issued.id })} size="lg" closeOnClickOutside={false}>
      <Stack gap="sm">
        <Alert color="orange" variant="light">
          {t('The private key is shown only now: the relay does not keep it. Save the three files on the machine that will run the gateway.')}
        </Alert>
        {files.map((f) => (
          <Group key={f.name} justify="space-between" wrap="nowrap">
            <Code>{f.name}</Code>
            <Group gap={4} wrap="nowrap">
              <CopyButton value={f.text}>
                {({ copied, copy }) => (
                  <Button size="compact-sm" variant="light" onClick={copy} leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />}>
                    {copied ? t('Copied') : t('Copy')}
                  </Button>
                )}
              </CopyButton>
              <Button size="compact-sm" variant="light" leftSection={<IconDownload size={14} />} onClick={() => download(f.name, f.text)}>{t('Download')}</Button>
            </Group>
          </Group>
        ))}
        <Text size="sm">{t('Then run it with:')}</Text>
        <Code block>{`proxygateway -relay RELAY_HOST:PORT -cert gateway.pem -key gateway-key.pem -ca ca.pem`}</Code>
        <Group justify="flex-end"><Button onClick={onClose}>{t('Done')}</Button></Group>
      </Stack>
    </Modal>
  )
}
