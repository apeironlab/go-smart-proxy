import { useEffect, useMemo, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Card, Code, Drawer, Group, SimpleGrid, Stack, Switch, Table, Text, TextInput, Title,
} from '@mantine/core'
import { IconSearch, IconX } from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'
import type { ConnInfo } from '../api'

const stateColors: Record<string, string> = {
  connecting: 'gray',
  authenticating: 'yellow',
  authenticated: 'green',
  established: 'teal',
  done: 'blue',
  failed: 'red',
  closed: 'gray',
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

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <Text size="xs" c="dimmed">{label}</Text>
      <Text size="sm" style={{ wordBreak: 'break-all' }}>{value}</Text>
    </div>
  )
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
      <Group justify="space-between" mb="md">
        <Title order={3}>{t('Connections')}</Title>
        <Group>
          <TextInput
            placeholder={t('Filter by host, URL, proxy, route...')}
            leftSection={<IconSearch size={14} />}
            value={filter}
            onChange={(e) => setFilter(e.currentTarget.value)}
            rightSection={filter ? (
              <ActionIcon size="sm" variant="subtle" color="gray" onClick={() => setFilter('')}>
                <IconX size={12} />
              </ActionIcon>
            ) : null}
            w={300}
          />
          <Switch
            label={t('Show closed')}
            checked={showClosed}
            onChange={(e) => setShowClosed(e.currentTarget.checked)}
          />
        </Group>
      </Group>

      {error && <Alert color="red" mb="md">{t('Failed to load: {{error}}', { error })}</Alert>}

      <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} mb="md">
        <Card withBorder><Text size="sm" c="dimmed">{t('Active connections')}</Text><Text fw={700} size="xl">{active}</Text></Card>
        <Card withBorder><Text size="sm" c="dimmed">Client → proxy</Text><Text fw={700} size="lg">{fmtBytes(totals.in)}</Text></Card>
        <Card withBorder><Text size="sm" c="dimmed">Proxy → client</Text><Text fw={700} size="lg">{fmtBytes(totals.out)}</Text></Card>
        <Card withBorder>
          <Text size="sm" c="dimmed">Upstream in / out</Text>
          <Text fw={700} size="lg">{fmtBytes(totals.upIn)} / {fmtBytes(totals.upOut)}</Text>
        </Card>
      </SimpleGrid>

      <Table striped highlightOnHover withTableBorder stickyHeader stickyHeaderOffset={0}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>#</Table.Th>
            <Table.Th>{t('Type')}</Table.Th>
            <Table.Th>{t('From')}</Table.Th>
            <Table.Th>{t('Requested host')}</Table.Th>
            <Table.Th>{t('To')}</Table.Th>
            <Table.Th>Proxy</Table.Th>
            <Table.Th>Route</Table.Th>
            <Table.Th>Auth</Table.Th>
            <Table.Th>{t('State')}</Table.Th>
            <Table.Th>↓ client</Table.Th>
            <Table.Th>↑ client</Table.Th>
            <Table.Th>↓ upstream</Table.Th>
            <Table.Th>↑ upstream</Table.Th>
            <Table.Th>{t('Duration')}</Table.Th>
            <Table.Th />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {filtered.map((c) => (
            <Table.Tr key={c.id} onClick={() => setSelectedId(c.id)} style={{ cursor: 'pointer' }}>
              <Table.Td>{c.id}</Table.Td>
              <Table.Td><Badge variant="light" color="gray" size="sm">{c.type}</Badge></Table.Td>
              <Table.Td><Text size="sm" truncate="end" maw={130}>{c.client || '-'}</Text></Table.Td>
              <Table.Td><Text size="sm" truncate="end" maw={220} title={c.host}>{c.host || '-'}</Text></Table.Td>
              <Table.Td><Text size="sm" truncate="end" maw={170}>{c.target || '-'}</Text></Table.Td>
              <Table.Td><Text size="sm" truncate="end" maw={130}>{c.proxy || '-'}</Text></Table.Td>
              <Table.Td><Text size="sm" truncate="end" maw={110}>{c.route || '-'}</Text></Table.Td>
              <Table.Td><Badge size="sm" color={authColors[c.auth] ?? 'gray'} variant="light">{c.auth}</Badge></Table.Td>
              <Table.Td><Badge size="sm" color={stateColors[c.state] ?? 'gray'} variant="light">{c.state}</Badge></Table.Td>
              <Table.Td><Text size="xs">{fmtBytes(c.bytesClientIn)}</Text></Table.Td>
              <Table.Td><Text size="xs">{fmtBytes(c.bytesClientOut)}</Text></Table.Td>
              <Table.Td><Text size="xs">{fmtBytes(c.bytesUpIn)}</Text></Table.Td>
              <Table.Td><Text size="xs">{fmtBytes(c.bytesUpOut)}</Text></Table.Td>
              <Table.Td><Text size="xs">{fmtDur(c)}</Text></Table.Td>
              <Table.Td onClick={(e) => e.stopPropagation()}>
                {!c.ended && (
                  <ActionIcon size="sm" color="red" variant="subtle" title={t('Close connection')}
                    onClick={() => api.closeConnection(c.id)}>
                    <IconX size={14} />
                  </ActionIcon>
                )}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>

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
