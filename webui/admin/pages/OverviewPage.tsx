import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ActionIcon, Alert, Badge, Group, SimpleGrid, Table, Text, Tooltip } from '@mantine/core'
import { IconActivity, IconCertificate, IconDeviceLaptop, IconHourglass, IconPlugConnectedX, IconUserCheck, IconUsers } from '@tabler/icons-react'
import { ContextBadges } from '../../src/components/contextBadges'
import { Dot, EmptyState, PageHeader, Section, StatCard } from '../../src/components/ui'
import { adminApi } from '../api'
import { fmtAgo, fmtDate, fmtDuration } from '../format'
import { message, usePolling } from '../hooks'
import { EventKind } from './AuditPage'

export default function OverviewPage() {
  const { t } = useTranslation()
  const { data, error, reload } = usePolling(adminApi.overview, 3000)
  const [problem, setProblem] = useState<string | null>(null)

  const kick = async (email: string) => {
    try {
      await adminApi.kick(email)
      reload()
    } catch (e) {
      setProblem(message(e))
    }
  }

  const c = data?.counts
  return (
    <>
      <PageHeader
        icon={IconActivity} title={t('Overview')}
        description={t('What the relay is doing right now. This page updates by itself.')}
        actions={data && <Badge variant="light" color="green" tt="none">{t('Up for {{time}}', { time: fmtDuration(data.uptime) })}</Badge>}
      />
      {(error || problem) && <Alert color="red" variant="light" mb="md">{problem ?? error}</Alert>}
      <SimpleGrid cols={{ base: 2, sm: 3, lg: 6 }} mb="lg">
        <StatCard label={t('Devices online')} value={c?.devices ?? '-'} icon={IconDeviceLaptop} color="green" />
        <StatCard label={t('People online')} value={c?.users ?? '-'} icon={IconUsers} color="teal" />
        <StatCard label={t('Certificates')} value={c?.certs ?? '-'} icon={IconCertificate} />
        <StatCard label={t('Expiring soon')} value={c?.expiring ?? '-'} icon={IconHourglass} color={c?.expiring ? 'orange' : 'gray'} />
        <StatCard label={t('Pending requests')} value={c?.pending ?? '-'} icon={IconUserCheck} color={c?.pending ? 'yellow' : 'gray'} />
        <StatCard label={t('Revoked')} value={c ? c.revokedCerts + c.revokedUsers : '-'} icon={IconPlugConnectedX} color={c && c.revokedCerts + c.revokedUsers ? 'red' : 'gray'}
          hint={c ? t('{{certs}} certificates, {{users}} identities', { certs: c.revokedCerts, users: c.revokedUsers }) : undefined} />
      </SimpleGrid>

      <Section title={t('Connected devices')} description={t('Each device keeps one connection to the relay.')}>
        {data && data.online.length === 0 ? (
          <EmptyState icon={IconDeviceLaptop} title={t('Nobody is connected')} />
        ) : (
          <Table.ScrollContainer minWidth={640}>
            <Table highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('User')}</Table.Th>
                  <Table.Th>{t('Device')}</Table.Th>
                  <Table.Th>{t('Network')}</Table.Th>
                  <Table.Th>{t('Address')}</Table.Th>
                  <Table.Th>{t('Connected')}</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {(data?.online ?? []).map((d) => (
                  <Table.Tr key={d.email + '/' + d.device}>
                    <Table.Td><Group gap={6} wrap="nowrap"><Dot color="green" /><Text size="sm">{d.email}</Text></Group></Table.Td>
                    <Table.Td><Text size="sm">{d.device}</Text></Table.Td>
                    <Table.Td><ContextBadges context={d.context} online /></Table.Td>
                    <Table.Td><Text size="sm" ff="monospace">{d.addr}</Text></Table.Td>
                    <Table.Td><Tooltip label={fmtDate(d.since)}><Text size="sm">{t('{{time}} ago', { time: fmtAgo(d.since) })}</Text></Tooltip></Table.Td>
                    <Table.Td>
                      <Tooltip label={t('Disconnect this user')}>
                        <ActionIcon variant="subtle" color="red" aria-label={t('Disconnect this user')} onClick={() => { void kick(d.email) }}>
                          <IconPlugConnectedX size={16} />
                        </ActionIcon>
                      </Tooltip>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Section>

      <Section title={t('Latest events')}>
        {(data?.recent ?? []).length === 0 ? (
          <Text size="sm" c="dimmed">{t('Nothing has happened yet.')}</Text>
        ) : (
          <Table verticalSpacing="xs">
            <Table.Tbody>
              {(data?.recent ?? []).map((e) => (
                <Table.Tr key={e.id}>
                  <Table.Td w={170}><Text size="xs" c="dimmed">{fmtDate(e.time)}</Text></Table.Td>
                  <Table.Td w={200}><EventKind kind={e.kind} /></Table.Td>
                  <Table.Td><Text size="sm" truncate>{[e.actor, e.subject].filter(Boolean).join(' → ')}</Text></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Section>
    </>
  )
}
