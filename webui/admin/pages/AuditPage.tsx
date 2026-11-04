import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert, Badge, Button, Group, Select, Table, Text, TextInput } from '@mantine/core'
import { IconHistory, IconSearch } from '@tabler/icons-react'
import { EmptyState, PageHeader, Section } from '../../src/components/ui'
import { adminApi } from '../api'
import type { AdminEvent } from '../api'
import { fmtDate } from '../format'
import { message } from '../hooks'

const colors: Record<string, string> = {
  'enroll.issued': 'green', 'enroll.request': 'blue', 'enroll.denied': 'orange',
  'admin.login': 'brand', 'admin.logout': 'gray', 'admin.denied': 'red', 'admin.revoke': 'red', 'admin.unrevoke': 'teal',
  'admin.kick': 'orange', 'admin.rules': 'grape', 'session.open': 'green', 'session.close': 'gray', 'session.refused': 'red',
}

export function EventKind({ kind }: { kind: string }) {
  return <Badge variant="light" color={colors[kind] ?? (kind.startsWith('admin.user') ? 'cyan' : 'gray')} tt="none">{kind}</Badge>
}

const PAGE = 100

export default function AuditPage() {
  const { t } = useTranslation()
  const [kind, setKind] = useState<string | null>('')
  const [search, setSearch] = useState('')
  const [applied, setApplied] = useState('')
  const [events, setEvents] = useState<AdminEvent[]>([])
  const [more, setMore] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async (before?: number) => {
    try {
      const rows = await adminApi.events({ kind: kind ?? '', q: applied, before, limit: PAGE })
      setEvents((old) => (before ? [...old, ...rows] : rows))
      setMore(rows.length === PAGE)
      setError(null)
    } catch (e) {
      setError(message(e))
    }
  }, [kind, applied])

  useEffect(() => { void load() }, [load])

  return (
    <>
      <PageHeader icon={IconHistory} title={t('Audit log')} description={t('Sign-ins, certificates, administrator actions and connections, newest first.')} />
      {error && <Alert color="red" variant="light" mb="md">{error}</Alert>}
      <Section>
        <Group align="flex-end" gap="sm" wrap="wrap">
          <Select
            label={t('Type')} value={kind} onChange={setKind} w={220} allowDeselect={false}
            data={[
              { value: '', label: t('All events') },
              { value: 'enroll.', label: t('Enrollment') },
              { value: 'admin.', label: t('Administration') },
              { value: 'session.', label: t('Connections') },
            ]}
          />
          <TextInput
            label={t('Search')} placeholder={t('e-mail, user, detail')} value={search} w={300}
            leftSection={<IconSearch size={14} />}
            onChange={(e) => setSearch(e.currentTarget.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') setApplied(search.trim()) }}
          />
          <Button variant="light" onClick={() => setApplied(search.trim())}>{t('Search')}</Button>
        </Group>
      </Section>
      <Section mb="md">
        {events.length === 0 ? (
          <EmptyState icon={IconHistory} title={t('No events')} />
        ) : (
          <Table.ScrollContainer minWidth={720}>
            <Table verticalSpacing="xs" highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('When')}</Table.Th>
                  <Table.Th>{t('Event')}</Table.Th>
                  <Table.Th>{t('Who')}</Table.Th>
                  <Table.Th>{t('Subject')}</Table.Th>
                  <Table.Th>{t('Detail')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {events.map((e) => (
                  <Table.Tr key={e.id}>
                    <Table.Td><Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>{fmtDate(e.time)}</Text></Table.Td>
                    <Table.Td><EventKind kind={e.kind} /></Table.Td>
                    <Table.Td><Text size="sm">{e.actor || '-'}</Text></Table.Td>
                    <Table.Td><Text size="sm" ff="monospace" style={{ wordBreak: 'break-all' }}>{e.subject || '-'}</Text></Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{e.detail || ''}</Text></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Section>
      {more && (
        <Group justify="center">
          <Button variant="default" onClick={() => { void load(events[events.length - 1]?.id) }}>{t('Show older events')}</Button>
        </Group>
      )}
    </>
  )
}
