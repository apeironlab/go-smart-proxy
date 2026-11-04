import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ActionIcon, Alert, Badge, Button, Group, Modal, PasswordInput, Stack, Table, Tabs, TagsInput, Text, Textarea, TextInput, Tooltip,
} from '@mantine/core'
import {
  IconBan, IconCertificate, IconMailPlus, IconCircleCheck, IconKey, IconPencil, IconPlus, IconTrash, IconUserCog, IconUsers,
} from '@tabler/icons-react'
import { Dot, EmptyState, PageHeader, Section } from '../../src/components/ui'
import { adminApi } from '../api'
import type { AdminDevice, CertRecord, InviteResult, LocalUser, UserInfo } from '../api'
import { fmtDate } from '../format'
import { message, usePolling } from '../hooks'

export default function UsersPage({ self }: { self: string }) {
  const { t } = useTranslation()
  const users = usePolling(adminApi.users, 5000)
  const locals = usePolling(adminApi.localUsers, 0)
  const [problem, setProblem] = useState<string | null>(null)
  const [certsOf, setCertsOf] = useState<string | null>(null)
  const [editing, setEditing] = useState<LocalUser | 'new' | null>(null)
  const [filter, setFilter] = useState('')
  const [inviting, setInviting] = useState(false)

  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      setProblem(null)
      users.reload()
      locals.reload()
    } catch (e) {
      setProblem(message(e))
    }
  }

  const shown = (users.data ?? []).filter((u) => u.email.includes(filter.trim().toLowerCase()))

  return (
    <>
      <PageHeader
        icon={IconUsers} title={t('Users and certificates')}
        description={t('Everybody who got a certificate from this relay. Revoking cuts live connections at once and refuses new ones.')}
        actions={<Button leftSection={<IconMailPlus size={16} />} onClick={() => setInviting(true)}>{t('Invite people')}</Button>}
      />
      {(problem || users.error) && <Alert color="red" variant="light" mb="md">{problem ?? users.error}</Alert>}
      <Tabs defaultValue="people" keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="people" leftSection={<IconCertificate size={15} />}>{t('People')}</Tabs.Tab>
          <Tabs.Tab value="local" leftSection={<IconUserCog size={15} />}>{t('Local password users')}</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="people">
          <Section>
            <TextInput placeholder={t('Filter by e-mail')} value={filter} onChange={(e) => setFilter(e.currentTarget.value)} mb="md" maw={360} />
            {shown.length === 0 ? (
              <EmptyState icon={IconUsers} title={t('No users')} text={t('Users appear here after they enroll.')} />
            ) : (
              <Table.ScrollContainer minWidth={700}>
                <Table highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t('User')}</Table.Th>
                      <Table.Th>{t('Valid certificates')}</Table.Th>
                      <Table.Th>{t('Last seen')}</Table.Th>
                      <Table.Th>{t('Status')}</Table.Th>
                      <Table.Th />
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {shown.map((u: UserInfo) => (
                      <Table.Tr key={u.email}>
                        <Table.Td>
                          <Group gap={6} wrap="nowrap"><Dot color={u.devices ? 'green' : 'gray'} /><Text size="sm">{u.email}</Text></Group>
                          {u.local && <Text size="xs" c="dimmed">{t('local user {{name}}', { name: u.local })}</Text>}
                        </Table.Td>
                        <Table.Td>{u.certs}</Table.Td>
                        <Table.Td><Text size="sm">{u.devices ? t('online ({{count}})', { count: u.devices }) : fmtDate(u.lastSeen)}</Text></Table.Td>
                        <Table.Td>{u.revoked ? <Badge color="red" variant="light">{t('revoked')}</Badge> : <Badge color="green" variant="light">{t('active')}</Badge>}</Table.Td>
                        <Table.Td>
                          <Group gap={4} justify="flex-end" wrap="nowrap">
                            <Tooltip label={t('Devices and certificates')}>
                              <ActionIcon variant="subtle" aria-label={t('Devices and certificates')} onClick={() => setCertsOf(u.email)}><IconCertificate size={16} /></ActionIcon>
                            </Tooltip>
                            {u.revoked ? (
                              <Tooltip label={t('Allow again')}>
                                <ActionIcon variant="subtle" color="teal" aria-label={t('Allow again')} onClick={() => { void act(() => adminApi.unrevoke({ email: u.email })) }}><IconCircleCheck size={16} /></ActionIcon>
                              </Tooltip>
                            ) : (
                              <Tooltip label={u.email === self ? t('You cannot revoke yourself') : t('Revoke all certificates')}>
                                <ActionIcon
                                  variant="subtle" color="red" disabled={u.email === self} aria-label={t('Revoke all certificates')}
                                  onClick={() => { if (window.confirm(t('Revoke every certificate of {{email}}?', { email: u.email }))) void act(() => adminApi.revoke({ email: u.email })) }}
                                ><IconBan size={16} /></ActionIcon>
                              </Tooltip>
                            )}
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
          </Section>
        </Tabs.Panel>

        <Tabs.Panel value="local">
          <Section
            title={t('Local password users')}
            description={t('Accounts kept in the relay database, for password methods set up with "database: true".')}
            right={locals.data?.enabled ? <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => setEditing('new')}>{t('Add user')}</Button> : undefined}
          >
            {locals.data && !locals.data.enabled && (
              <Alert color="yellow" variant="light" mb="md">
                {t('No password method uses the database. Add one to the authentication file (type password, database: true) for these users to be able to sign in.')}
              </Alert>
            )}
            {(locals.data?.users ?? []).length === 0 ? (
              <EmptyState icon={IconKey} title={t('No local users')} />
            ) : (
              <Table.ScrollContainer minWidth={600}>
                <Table>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t('User name')}</Table.Th>
                      <Table.Th>{t('E-mail')}</Table.Th>
                      <Table.Th>{t('Groups')}</Table.Th>
                      <Table.Th>{t('Created')}</Table.Th>
                      <Table.Th />
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {(locals.data?.users ?? []).map((u) => (
                      <Table.Tr key={u.username}>
                        <Table.Td><Text size="sm" fw={600}>{u.username}</Text></Table.Td>
                        <Table.Td><Text size="sm">{u.email}</Text></Table.Td>
                        <Table.Td><Group gap={4}>{u.groups.map((g) => <Badge key={g} variant="light" tt="none">{g}</Badge>)}</Group></Table.Td>
                        <Table.Td><Text size="sm" c="dimmed">{fmtDate(u.created)}</Text></Table.Td>
                        <Table.Td>
                          <Group gap={4} justify="flex-end" wrap="nowrap">
                            <Tooltip label={t('Edit or reset password')}>
                              <ActionIcon variant="subtle" aria-label={t('Edit or reset password')} onClick={() => setEditing(u)}><IconPencil size={16} /></ActionIcon>
                            </Tooltip>
                            <Tooltip label={t('Delete')}>
                              <ActionIcon
                                variant="subtle" color="red" aria-label={t('Delete')}
                                onClick={() => {
                                  if (window.confirm(t('Delete the user {{name}}? Certificates already issued stay valid until you revoke them.', { name: u.username }))) {
                                    void act(() => adminApi.deleteLocalUser(u.username))
                                  }
                                }}
                              ><IconTrash size={16} /></ActionIcon>
                            </Tooltip>
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
          </Section>
        </Tabs.Panel>
      </Tabs>

      {inviting && <InviteModal onClose={() => setInviting(false)} />}
      {certsOf && <DevicesModal email={certsOf} onClose={() => { setCertsOf(null); users.reload() }} />}
      {editing && (
        <LocalUserModal
          user={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); users.reload(); locals.reload() }}
        />
      )}
    </>
  )
}

function DevicesModal({ email, onClose }: { email: string; onClose: () => void }) {
  const { t } = useTranslation()
  const { data, error, reload } = usePolling(() => adminApi.devices(email), 4000)
  const [problem, setProblem] = useState<string | null>(null)
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      setProblem(null)
      reload()
    } catch (e) {
      setProblem(message(e))
    }
  }
  const now = Date.now()
  return (
    <Modal opened onClose={onClose} title={t('Devices of {{email}}', { email })} size="xl">
      {(problem || error) && <Alert color="red" variant="light" mb="md">{problem ?? error}</Alert>}
      {data && data.length === 0 && <Text size="sm" c="dimmed">{t('No device known for this address.')}</Text>}
      <Stack gap="lg">
        {(data ?? []).map((d: AdminDevice) => {
          const active = d.certs.filter((c) => !c.revoked && new Date(c.expires).getTime() > now)
          return (
            <div key={d.device}>
              <Group justify="space-between" wrap="nowrap" mb={4}>
                <Group gap={8} wrap="nowrap">
                  <Dot color={d.online ? 'green' : 'gray'} />
                  <Text fw={650}>{d.device}</Text>
                  {d.online && <Text size="xs" c="dimmed">{d.addr}</Text>}
                  {d.context?.vpn && <Badge variant="light" color="grape" size="sm">VPN</Badge>}
                  {d.context?.label && <Badge variant="outline" color="grape" size="sm" tt="none">{d.context.label}</Badge>}
                </Group>
                {active.length > 0 && (
                  <Button
                    size="compact-xs" variant="light" color="red"
                    onClick={() => { if (window.confirm(t('Revoke every certificate of the device {{device}} and disconnect it?', { device: d.device }))) void act(() => adminApi.revokeDevice(email, d.device)) }}
                  >{t('Revoke device')}</Button>
                )}
              </Group>
              {d.certs.length === 0 ? (
                <Text size="xs" c="dimmed">{t('Connected without a certificate recorded here (issued before the interface was enabled).')}</Text>
              ) : (
                <Table.ScrollContainer minWidth={560}>
                  <Table verticalSpacing="xs">
                    <Table.Tbody>
                      {d.certs.map((c: CertRecord) => {
                        const expired = new Date(c.expires).getTime() < now
                        return (
                          <Table.Tr key={c.serial}>
                            <Table.Td><Text size="xs" ff="monospace">{c.serial.slice(0, 16)}</Text></Table.Td>
                            <Table.Td><Text size="sm">{c.method || '-'}</Text></Table.Td>
                            <Table.Td><Text size="xs">{fmtDate(c.issued)}</Text></Table.Td>
                            <Table.Td>
                              {c.revoked ? <Badge color="red" variant="light">{t('revoked')}</Badge>
                                : expired ? <Badge color="gray" variant="light">{t('expired')}</Badge>
                                  : <Text size="xs">{fmtDate(c.expires)}</Text>}
                            </Table.Td>
                            <Table.Td>
                              {c.revoked ? (
                                <Button size="compact-xs" variant="light" color="teal" onClick={() => { void act(() => adminApi.unrevoke({ serial: c.serial })) }}>{t('Allow again')}</Button>
                              ) : !expired && (
                                <Button
                                  size="compact-xs" variant="subtle" color="red"
                                  onClick={() => { if (window.confirm(t('Revoke this certificate?'))) void act(() => adminApi.revoke({ serial: c.serial })) }}
                                >{t('Revoke')}</Button>
                              )}
                            </Table.Td>
                          </Table.Tr>
                        )
                      })}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              )}
            </div>
          )
        })}
      </Stack>
    </Modal>
  )
}

function InviteModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<InviteResult | null>(null)
  const send = async () => {
    setBusy(true)
    setError(null)
    try {
      setResult(await adminApi.invite(text.split(/[\s,;]+/).filter(Boolean)))
    } catch (e) {
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal opened onClose={onClose} title={t('Invite people')}>
      <Stack gap="sm">
        <Text size="sm" c="dimmed">{t('Each address gets an e-mail with where to get the proxy and the address of this relay. They then sign in as usual.')}</Text>
        {error && <Alert color="red" variant="light">{error}</Alert>}
        <Textarea
          label={t('E-mail addresses')} description={t('One per line, or separated by commas.')} minRows={4} autosize
          value={text} onChange={(e) => setText(e.currentTarget.value)} disabled={!!result}
        />
        {result && (
          <Stack gap={4}>
            <Alert color={result.sent ? 'green' : 'yellow'} variant="light">{t('{{count}} invitations sent.', { count: result.sent })}</Alert>
            {result.results.filter((r) => !r.ok).map((r) => <Text key={r.email} size="sm" c="red">{r.email}: {r.error}</Text>)}
          </Stack>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>{result ? t('Close') : t('Cancel')}</Button>
          {!result && <Button loading={busy} disabled={!text.trim()} onClick={() => { void send() }}>{t('Send')}</Button>}
        </Group>
      </Stack>
    </Modal>
  )
}

function LocalUserModal({ user, onClose, onSaved }: { user: LocalUser | null; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation()
  const [username, setUsername] = useState(user?.username ?? '')
  const [email, setEmail] = useState(user?.email ?? '')
  const [password, setPassword] = useState('')
  const [groups, setGroups] = useState<string[]>(user?.groups ?? [])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      if (user) await adminApi.editLocalUser(user.username, { password: password || undefined, email, groups })
      else await adminApi.addLocalUser({ username, password, email: email || username, groups })
      onSaved()
    } catch (e) {
      setError(message(e))
      setBusy(false)
    }
  }

  return (
    <Modal opened onClose={onClose} title={user ? t('Edit {{name}}', { name: user.username }) : t('Add a local user')}>
      <form onSubmit={(e) => { e.preventDefault(); void save() }}>
        <Stack gap="sm">
          {error && <Alert color="red" variant="light">{error}</Alert>}
          <TextInput label={t('User name')} value={username} onChange={(e) => setUsername(e.currentTarget.value)} disabled={!!user} required autoFocus={!user} />
          <TextInput label={t('E-mail')} description={t('The identity of the certificate. Defaults to the user name when that is an address.')} value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
          <PasswordInput
            label={user ? t('New password') : t('Password')} description={user ? t('Leave empty to keep the current one.') : t('At least 8 characters.')}
            value={password} onChange={(e) => setPassword(e.currentTarget.value)} required={!user} autoComplete="new-password"
          />
          <TagsInput label={t('Groups')} description={t('Used by "required groups" rules and to decide who is an administrator.')} value={groups} onChange={setGroups} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>{t('Cancel')}</Button>
            <Button type="submit" loading={busy}>{t('Save')}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
