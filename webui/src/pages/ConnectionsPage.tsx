import { useEffect, useMemo, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Card, Code, Drawer, Group, SimpleGrid, Stack, Switch, Table, Text, TextInput,
} from '@mantine/core'
import {
  IconArrowDown, IconArrowUp, IconPlugConnected, IconSearch, IconServer, IconUser, IconX,
} from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'
import type { ConnInfo } from '../api'
import { Dot, EmptyState, Info, PageHeader, StatCard } from '../components/ui'

const stateColors: Record<string, string> = {
  connecting: 'gray',
  authenticating: 'yellow',
  authenticated: 'green',
  established: 'teal',
  done: 'blue',
  failed: 'red',
  closed: 'gray',
  blocked: 'orange',
}

const authColors: Record<string, string> = {
  none: 'gray',
  ntlm: 'yellow',
  authenticated: 'green',
  failed: 'red',
}

export function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`
  return `${(n / 1073741824).toFixed(2)} GB`
}

function fmtDur(conn: ConnInfo) {
  const end = conn.ended ? new Date(conn.ended).getTime() : Date.now()
  const s = Math.max(0, Math.floor((end - new Date(conn.started).getTime()) / 1000))
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

function fmtTime(t: string) {
  const d = new Date(t)
  return `${d.toLocaleTimeString('it-IT')}.${String(d.getMilliseconds()).padStart(3, '0')}`
}

function ConnDetails({ conn }: { conn: ConnInfo }) {
  const { t } = useTranslation()
  return (
    <Stack gap="md">
      <Group gap="xs">
        <Badge color={stateColors[conn.state] ?? 'gray'}>{conn.state}</Badge>
        <Badge color={authColors[conn.auth] ?? 'gray'}>{conn.auth}</Badge>
        {conn.status > 0 && (
          <Badge color={conn.status < 400 ? 'green' : 'red'} variant="outline">HTTP {conn.status}</Badge>
        )}
      </Group>
      {conn.error && <Alert color="red" title={t('Error')}>{conn.error}</Alert>}
      <SimpleGrid cols={2}>
        <Info label="ID" value={String(conn.id)} />
        <Info label={t('Type')} value={conn.type} />
        <Info label={t('Method')} value={conn.method || '-'} />
        <Info label="URL" value={conn.url || '-'} />
        <Info label="Client" value={conn.client || '-'} />
        <Info label={t('Requested host')} value={conn.host || '-'} />
        <Info label={t('Connected target')} value={conn.target || '-'} />
        <Info label={t('Upstream proxy')} value={conn.proxy || '-'} />
        <Info label="Route" value={conn.route || '-'} />
        <Info label="Credential" value={conn.cred || '-'} />
        <Info label={t('Start')} value={fmtTime(conn.started)} />
        <Info label={t('End')} value={conn.ended ? fmtTime(conn.ended) : '-'} />
        <Info label={t('Duration')} value={fmtDur(conn)} />
      </SimpleGrid>
      <SimpleGrid cols={4}>
        <Info label="Client → proxy" value={fmtBytes(conn.bytesClientIn)} />
        <Info label="Proxy → client" value={fmtBytes(conn.bytesClientOut)} />
        <Info label="Proxy → upstream" value={fmtBytes(conn.bytesUpOut)} />
        <Info label="Upstream → proxy" value={fmtBytes(conn.bytesUpIn)} />
      </SimpleGrid>
      <div>
        <Text fw={700} mb="xs">{t('Events')}</Text>
        <Code block style={{ maxHeight: 300, overflow: 'auto' }}>
          {(conn.events ?? []).map((e) => `${fmtTime(e.time)}  ${e.msg}`).join('\n') || t('(no events)')}
        </Code>
      </div>
    </Stack>
  )
}

export default function ConnectionsPage() {
  const { t } = useTranslation()
  const [conns, setConns] = useState<ConnInfo[]>([])
  const [showClosed, setShowClosed] = useState(false)
  const [filter, setFilter] = useState('')
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = () =>
      api
        .connections(showClosed)
        .then(setConns)
        .catch((e) => setError(String(e)))
    load()
    const timer = setInterval(load, 2000)
    return () => clearInterval(timer)
  }, [showClosed])

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return conns
    return conns.filter((c) =>
      [c.host, c.url, c.target, c.client, c.proxy, c.route].some((v) => (v ?? '').toLowerCase().includes(q)),
    )
  }, [conns, filter])

  const selected = conns.find((c) => c.id === selectedId) ?? null
  const active = useMemo(() => conns.filter((c) => !c.ended).length, [conns])
  const totals = useMemo(
    () =>
      conns.reduce(
        (acc, c) => ({
          in: acc.in + c.bytesClientIn,
          out: acc.out + c.bytesClientOut,
          upIn: acc.upIn + c.bytesUpIn,
          upOut: acc.upOut + c.bytesUpOut,
        }),
        { in: 0, out: 0, upIn: 0, upOut: 0 },
      ),
    [conns],
  )

  return (
    <>
      <PageHeader
        icon={IconPlugConnected}
        title={t('Connections')}
        description={t('Live view of the traffic going through the proxy. Click a row for the details and the event log.')}
        actions={
          <>
            <TextInput
              placeholder={t('Filter by host, URL, proxy, route...')}
              leftSection={<IconSearch size={14} />}
              value={filter}
              onChange={(e) => setFilter(e.currentTarget.value)}
              rightSection={filter ? (
                <ActionIcon size="sm" variant="subtle" color="gray" onClick={() => setFilter('')} aria-label={t('Clear')}>
                  <IconX size={12} />
                </ActionIcon>
              ) : null}
              w={{ base: '100%', sm: 300 }}
            />
            <Switch
              label={t('Show closed')}
              checked={showClosed}
              onChange={(e) => setShowClosed(e.currentTarget.checked)}
            />
          </>
        }
      />

      {error && <Alert color="red" mb="md">{t('Failed to load: {{error}}', { error })}</Alert>}

      <SimpleGrid cols={{ base: 2, md: 4 }} mb="lg">
        <StatCard label={t('Active connections')} value={active} icon={IconPlugConnected} color="teal" />
        <StatCard label="Client → proxy" value={fmtBytes(totals.in)} icon={IconUser} color="brand" />
        <StatCard label="Proxy → client" value={fmtBytes(totals.out)} icon={IconUser} color="grape" />
        <StatCard
          label={t('Upstream in / out')}
          value={`${fmtBytes(totals.upIn)} / ${fmtBytes(totals.upOut)}`}
          icon={IconServer}
          color="cyan"
        />
      </SimpleGrid>

      <Card withBorder padding={0}>
        {filtered.length === 0 ? (
          <EmptyState
            icon={IconPlugConnected}
            title={filter ? t('No connection matches the filter') : t('No connections yet')}
            text={filter ? undefined : t('Traffic will appear here as soon as an application uses the proxy.')}
          />
        ) : (
          <Table.ScrollContainer minWidth={900}>
            <Table highlightOnHover style={{ border: 0, borderRadius: 0 }}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>#</Table.Th>
                  <Table.Th>{t('Destination')}</Table.Th>
                  <Table.Th>{t('Route')}</Table.Th>
                  <Table.Th>{t('State')}</Table.Th>
                  <Table.Th>{t('Traffic')}</Table.Th>
                  <Table.Th>{t('Duration')}</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {filtered.map((c) => (
                  <Table.Tr key={c.id} onClick={() => setSelectedId(c.id)} style={{ cursor: 'pointer' }}>
                    <Table.Td c="dimmed">{c.id}</Table.Td>
                    <Table.Td>
                      <Group gap={8} wrap="nowrap">
                        <Badge variant="light" color="gray" size="sm" radius="sm">{c.type}</Badge>
                        <div style={{ minWidth: 0 }}>
                          <Text size="sm" fw={600} truncate="end" maw={280} title={c.host || c.target}>
                            {c.host || c.target || '-'}
                          </Text>
                          <Text size="xs" c="dimmed" truncate="end" maw={280}>
                            {t('from')} {c.client || '-'}{c.target && c.host ? ` · ${c.target}` : ''}
                          </Text>
                        </div>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" truncate="end" maw={180}>{c.route || '-'}</Text>
                      <Text size="xs" c="dimmed" truncate="end" maw={180}>{c.proxy || t('direct')}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        <Dot color={stateColors[c.state] ?? 'gray'} />
                        <Text size="sm">{c.state}</Text>
                      </Group>
                      <Badge size="xs" mt={2} color={authColors[c.auth] ?? 'gray'} variant="light" radius="sm">{c.auth}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={10} wrap="nowrap">
                        <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>
                          <IconArrowDown size={11} style={{ verticalAlign: -1 }} /> {fmtBytes(c.bytesClientIn)}
                          {' '}
                          <IconArrowUp size={11} style={{ verticalAlign: -1 }} /> {fmtBytes(c.bytesClientOut)}
                        </Text>
                      </Group>
                      <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }} title="upstream">
                        <IconServer size={11} style={{ verticalAlign: -1 }} /> {fmtBytes(c.bytesUpIn)} / {fmtBytes(c.bytesUpOut)}
                      </Text>
                    </Table.Td>
                    <Table.Td><Text size="sm" style={{ whiteSpace: 'nowrap' }}>{fmtDur(c)}</Text></Table.Td>
                    <Table.Td onClick={(e) => e.stopPropagation()}>
                      {!c.ended && (
                        <ActionIcon size="sm" color="red" variant="subtle" title={t('Close connection')}
                          aria-label={t('Close connection')} onClick={() => api.closeConnection(c.id)}>
                          <IconX size={14} />
                        </ActionIcon>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>

      <Drawer
        opened={!!selected}
        onClose={() => setSelectedId(null)}
        position="right"
        size="lg"
        title={selected ? t('Connection #{{id}}', { id: selected.id }) : ''}
      >
        {selected && <ConnDetails conn={selected} />}
      </Drawer>
    </>
  )
}
