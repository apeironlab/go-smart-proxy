import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ActionIcon, Alert, Badge, Button, Checkbox, Code, Group, SegmentedControl, SimpleGrid, Stack, Switch, Table, TagsInput, Text, TextInput, Tooltip,
} from '@mantine/core'
import { IconBan, IconBuildingSkyscraper, IconPlus, IconRefresh, IconSearch, IconShieldCheck, IconTrash } from '@tabler/icons-react'
import { api } from '../api'
import type { BlockingConfig, BlockingInfo, BlockingTest } from '../api'
import { EmptyState, PageHeader, Section, StatCard } from '../components/ui'
import { usePolled } from '../usePolled'

const empty: BlockingConfig = { enabled: false, presets: [], lists: [], block: [], allow: [], relayOff: [], refreshHours: 0 }

const fmt = (v?: string) => (v && !v.startsWith('0001') ? new Date(v).toLocaleString() : '-')

export default function ProtectionPage() {
  const { t } = useTranslation()
  const info = usePolled<BlockingInfo>(api.blocking, 4000)
  const stats = usePolled(api.blockingStats, 3000)
  const [cfg, setCfg] = useState<BlockingConfig>(empty)
  const [loaded, setLoaded] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [newName, setNewName] = useState('')
  const [newUrl, setNewUrl] = useState('')
  const [host, setHost] = useState('')
  const [test, setTest] = useState<BlockingTest | null>(null)

  // Take the configuration from the proxy once, then leave it to the user until saved.
  useEffect(() => {
    if (info && !loaded) {
      setCfg(info.config)
      setLoaded(true)
    }
  }, [info, loaded])

  const update = (patch: Partial<BlockingConfig>) => {
    setCfg((c) => ({ ...c, ...patch }))
    setDirty(true)
    setSaved(false)
  }

  const save = async () => {
    setError(null)
    try {
      const r = await api.saveBlocking(cfg)
      setCfg(r.config)
      setDirty(false)
      setSaved(true)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const togglePreset = (id: string, on: boolean) =>
    update({ presets: on ? [...cfg.presets, id] : cfg.presets.filter((p) => p !== id) })

  const toggleRelayRule = (relay: string, id: string, on: boolean) => {
    const key = `${relay}/${id}`
    update({ relayOff: on ? cfg.relayOff.filter((k) => k !== key) : [...cfg.relayOff, key] })
  }

  const statusOf = (url: string) => info?.lists.find((l) => l.key === url)

  const runTest = async () => {
    if (!host.trim()) return
    try {
      setTest(await api.testBlocking(host.trim()))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const orgBlocks = (info?.relays ?? []).reduce((n, r) => n + r.mandatory, 0)

  return (
    <>
      <PageHeader
        icon={IconShieldCheck} title={t('Protection')}
        description={t('Block ads, trackers and malicious sites before any connection is made, whatever route it would take. It works without a relay too.')}
        actions={
          <>
            <Button variant="default" leftSection={<IconRefresh size={16} />} loading={info?.updating} onClick={() => { void api.refreshBlocking() }}>{t('Update lists')}</Button>
            <Button disabled={!dirty} onClick={() => { void save() }}>{t('Save changes')}</Button>
          </>
        }
      />
      {error && <Alert color="red" variant="light" mb="md" withCloseButton onClose={() => setError(null)}>{error}</Alert>}
      {saved && <Alert color="green" variant="light" mb="md" withCloseButton onClose={() => setSaved(false)}>{t('Saved.')}</Alert>}

      <SimpleGrid cols={{ base: 1, sm: 3 }} mb="lg">
        <StatCard label={t('Blocked since start')} value={stats?.total ?? '-'} icon={IconBan} color={stats?.total ? 'orange' : 'gray'} />
        <StatCard label={t('Blocking')} value={cfg.enabled ? t('on') : t('off')} icon={IconShieldCheck} color={cfg.enabled ? 'green' : 'gray'} />
        <StatCard label={t('Your organization')} value={orgBlocks} icon={IconBuildingSkyscraper} hint={t('rules you cannot change')} />
      </SimpleGrid>

      <Section>
        <Switch
          size="md" checked={cfg.enabled} onChange={(e) => update({ enabled: e.currentTarget.checked })}
          label={t('Block ads, trackers and malicious sites')}
          description={t('The proxy refuses connections to hosts on the lists below. Your organization\'s rules apply either way.')}
        />
      </Section>

      <Section title={t('Lists')} description={t('Lists are downloaded now and then and kept on this computer. A domain on a list blocks its subdomains too.')}>
        <Stack gap="sm">
          {(info?.presets ?? []).map((p) => {
            const st = statusOf(p.url)
            return (
              <Group key={p.id} justify="space-between" wrap="nowrap" align="flex-start">
                <Checkbox
                  checked={cfg.presets.includes(p.id)} onChange={(e) => togglePreset(p.id, e.currentTarget.checked)}
                  label={p.name} description={p.description}
                />
                {cfg.presets.includes(p.id) && !dirty && st && (
                  <Text size="xs" c={st.error ? 'red' : 'dimmed'} ta="right">
                    {st.error || t('{{count}} entries · {{date}}', { count: st.entries, date: fmt(st.fetched) })}
                  </Text>
                )}
              </Group>
            )
          })}
          {cfg.lists.length > 0 && (
            <Table verticalSpacing="xs">
              <Table.Tbody>
                {cfg.lists.map((l, i) => {
                  const st = statusOf(l.url)
                  return (
                    <Table.Tr key={l.url}>
                      <Table.Td w={40}>
                        <Checkbox
                          checked={l.enabled} aria-label={l.name}
                          onChange={(e) => update({ lists: cfg.lists.map((x, j) => (j === i ? { ...x, enabled: e.currentTarget.checked } : x)) })}
                        />
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" fw={600}>{l.name}</Text>
                        <Text size="xs" c="dimmed" style={{ wordBreak: 'break-all' }}>{l.url}</Text>
                        {l.enabled && !dirty && st && (
                          <Text size="xs" c={st.error ? 'red' : 'dimmed'}>{st.error || t('{{count}} entries · {{date}}', { count: st.entries, date: fmt(st.fetched) })}</Text>
                        )}
                      </Table.Td>
                      <Table.Td w={40}>
                        <Tooltip label={t('Remove')}>
                          <ActionIcon variant="subtle" color="red" aria-label={t('Remove')} onClick={() => update({ lists: cfg.lists.filter((_, j) => j !== i) })}>
                            <IconTrash size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Table.Td>
                    </Table.Tr>
                  )
                })}
              </Table.Tbody>
            </Table>
          )}
          <Group align="flex-end" gap="sm" wrap="wrap">
            <TextInput label={t('Name')} value={newName} onChange={(e) => setNewName(e.currentTarget.value)} w={180} />
            <TextInput
              label={t('Address of a list')} placeholder="https://example.com/hosts.txt" value={newUrl}
              onChange={(e) => setNewUrl(e.currentTarget.value)} style={{ flex: 1, minWidth: 220 }}
              description={t('Hosts files, domain lists and adblock lists (||domain^) are understood.')}
            />
            <Button
              variant="light" leftSection={<IconPlus size={16} />} disabled={!newName.trim() || !newUrl.trim()}
              onClick={() => {
                update({ lists: [...cfg.lists, { name: newName.trim(), url: newUrl.trim(), format: 'auto', enabled: true }] })
                setNewName('')
                setNewUrl('')
              }}
            >{t('Add')}</Button>
          </Group>
          <SegmentedControl
            size="xs" w="fit-content" value={String(cfg.refreshHours || 24)} onChange={(v) => update({ refreshHours: Number(v) })}
            data={[{ value: '6', label: t('every 6 h') }, { value: '24', label: t('daily') }, { value: '168', label: t('weekly') }]}
          />
        </Stack>
      </Section>

      <Section title={t('Your own rules')}>
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <TagsInput
            label={t('Always block')} value={cfg.block} onChange={(v) => update({ block: v })} placeholder="ads.example.com"
            description={t('Host names (subdomains included), addresses or networks like 203.0.113.0/24.')}
          />
          <TagsInput
            label={t('Never block')} value={cfg.allow} onChange={(v) => update({ allow: v })} placeholder="example.com"
            description={t('For a site a list blocks by mistake. It does not override your organization\'s rules.')}
          />
        </SimpleGrid>
      </Section>

      {(info?.relays ?? []).length > 0 && (
        <Section
          title={t('From your relays')}
          description={t('Rules set by the people who run your relay. Required ones always apply; recommended ones you can switch off.')}
        >
          <Stack gap="sm">
            {(info?.relays ?? []).map((r) => (
              <div key={r.relay}>
                <Group gap="xs" mb={4}>
                  <Text fw={600} size="sm">{r.relay}</Text>
                  {r.mandatory > 0 && <Badge variant="light" color="orange" tt="none">{t('{{count}} required rules', { count: r.mandatory })}</Badge>}
                </Group>
                {r.recommended.map((x) => (
                  <Checkbox
                    key={x.id} mb={4} checked={x.enabled} label={x.name}
                    onChange={(e) => toggleRelayRule(r.relay, x.id, e.currentTarget.checked)}
                  />
                ))}
              </div>
            ))}
          </Stack>
        </Section>
      )}

      <Section title={t('Check a host')} description={t('See whether a host is blocked, and why.')}>
        <Group align="flex-end" gap="sm">
          <TextInput value={host} onChange={(e) => setHost(e.currentTarget.value)} placeholder="ads.example.com" style={{ flex: 1 }}
            onKeyDown={(e) => { if (e.key === 'Enter') void runTest() }} />
          <Button variant="light" leftSection={<IconSearch size={16} />} onClick={() => { void runTest() }}>{t('Check')}</Button>
        </Group>
        {test && (
          <Alert mt="sm" variant="light" color={test.blocked ? 'orange' : 'green'}>
            {test.blocked
              ? (test.mandatory ? t('{{host}} is blocked by your organization.', { host: test.host }) : t('{{host}} is blocked by {{source}} ({{rule}}).', { host: test.host, source: test.source, rule: test.rule }))
              : t('{{host}} is not blocked.', { host: test.host })}
          </Alert>
        )}
      </Section>

      <Section
        title={t('Recently blocked')}
        right={stats && stats.total > 0 ? <Button size="xs" variant="subtle" color="gray" onClick={() => { void api.resetBlockingStats() }}>{t('Reset counters')}</Button> : undefined}
      >
        {!stats || stats.recent.length === 0 ? (
          <EmptyState icon={IconBan} title={t('Nothing blocked yet')} />
        ) : (
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <Table verticalSpacing="xs">
              <Table.Thead><Table.Tr><Table.Th>{t('Most blocked')}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
              <Table.Tbody>
                {stats.top.map((h) => (
                  <Table.Tr key={h.host}><Table.Td><Code>{h.host}</Code></Table.Td><Table.Td ta="right">{h.count}</Table.Td></Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            <Table verticalSpacing="xs">
              <Table.Thead><Table.Tr><Table.Th>{t('Latest')}</Table.Th><Table.Th>{t('By')}</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {stats.recent.slice(0, 10).map((e, i) => (
                  <Table.Tr key={i}>
                    <Table.Td><Text size="sm" truncate>{e.host}</Text><Text size="xs" c="dimmed">{new Date(e.time).toLocaleTimeString()}</Text></Table.Td>
                    <Table.Td><Text size="xs" c="dimmed">{e.source}</Text></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </SimpleGrid>
        )}
      </Section>
    </>
  )
}
