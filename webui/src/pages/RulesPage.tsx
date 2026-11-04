import { useCallback, useEffect, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Button, Card, Code, Group, Modal, Select, Stack, Table, TagsInput, Text, TextInput,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import {
  IconArrowDown, IconArrowUp, IconPencil, IconPlus, IconRoute, IconSearch, IconTrash,
} from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'
import type { RoutingRule, RuleTest } from '../api'
import { EmptyState, PageHeader, Section } from '../components/ui'

const empty: RoutingRule = { name: '', domains: [], hosts: [], networks: [], route: '', exitVpn: '', exitLabel: '' }

// The backend may send null for empty lists (older versions, or hand-edited
// config.yml): normalize them so the page can always use .length and .map.
const normalize = (r: RoutingRule): RoutingRule => ({
  ...r,
  domains: r.domains ?? [],
  hosts: r.hosts ?? [],
  networks: r.networks ?? [],
})

export default function RulesPage() {
  const { t } = useTranslation()
  const [rules, setRules] = useState<RoutingRule[]>([])
  const [routeNames, setRouteNames] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [opened, { open, close }] = useDisclosure(false)
  const [editIdx, setEditIdx] = useState<number | null>(null)
  const [form, setForm] = useState<RoutingRule>(empty)
  const [testHost, setTestHost] = useState('')
  const [testRes, setTestRes] = useState<RuleTest | null>(null)

  const load = useCallback(() => {
    api.rules().then((r) => setRules((r ?? []).map(normalize))).catch((e) => setError(String(e)))
    api.routes().then((r) => setRouteNames(r.map((x) => x.name))).catch(() => {})
  }, [])
  useEffect(load, [load])

  const persist = async (next: RoutingRule[]) => {
    try {
      setError(null)
      await api.saveRules(next)
      setRules(next)
      return true
    } catch (e) {
      setError(String(e))
      return false
    }
  }

  const move = (i: number, d: number) => {
    const next = [...rules]
    ;[next[i], next[i + d]] = [next[i + d], next[i]]
    persist(next)
  }

  const routeOptions = Array.from(new Set([...routeNames, 'Direct']))

  const save = async () => {
    const next = [...rules]
    if (editIdx === null) next.push(form)
    else next[editIdx] = form
    if (await persist(next)) close()
  }

  const test = async () => {
    try {
      setTestRes(await api.testRule(testHost.trim()))
    } catch (e) {
      setError(String(e))
    }
  }

  const tags = (v: string[]) => v.map((x) => <Badge key={x} variant="light" size="sm" radius="sm" tt="none">{x}</Badge>)

  return (
    <Stack gap={0}>
      <PageHeader
        icon={IconRoute}
        title={t('Destination rules')}
        description={<>
          {t('Rules are evaluated only with')} <b>Auto</b>{' '}
          {t('selection (or explicitly from a')} <b>Dynamic</b>{' '}
          {t('hop), in order: the first matching rule whose route is applicable on the current network wins. If none matches, normal selection is used. A forced route takes precedence and disables the rules.')}
        </>}
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => { setEditIdx(null); setForm(empty); open() }}>
            {t('New rule')}
          </Button>
        }
      />
      {error && <Alert color="red" withCloseButton onClose={() => setError(null)} mb="md">{error}</Alert>}

      <Section
        title={t('Test a destination')}
        description={t('Check which route a host or IP would use with the current rules.')}
      >
        <Group gap="xs" align="flex-end">
          <TextInput placeholder={t('www.example.com or 10.1.2.3')} value={testHost} w={{ base: '100%', sm: 340 }}
            leftSection={<IconSearch size={14} />}
            onChange={(e) => setTestHost(e.currentTarget.value)}
            onKeyDown={(e) => e.key === 'Enter' && testHost.trim() && test()} />
          <Button variant="light" onClick={test} disabled={!testHost.trim()}>{t('Test')}</Button>
        </Group>
        {testRes && (
          <Card withBorder mt="md" padding="sm" bg="var(--mantine-color-default-hover)">
            <Text size="sm">
              {testRes.ip && <>IP <Code>{testRes.ip}</Code> · </>}
              {t('route')} <b>{testRes.route ?? t('none')}</b>
              {testRes.rule ? <> ({t('rule')} <b>{testRes.rule}</b>)</> : <> ({t('normal selection')})</>}
            </Text>
          </Card>
        )}
      </Section>

      <Card withBorder padding={0}>
        {!rules.length ? (
          <EmptyState
            icon={IconRoute}
            title={t('No rules')}
            text={t('Create a rule to send specific domains, hosts or networks through a dedicated route.')}
            action={
              <Button mt="xs" leftSection={<IconPlus size={16} />} onClick={() => { setEditIdx(null); setForm(empty); open() }}>
                {t('New rule')}
              </Button>
            }
          />
        ) : (
          <Table.ScrollContainer minWidth={640}>
            <Table highlightOnHover style={{ border: 0, borderRadius: 0 }}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={50}>#</Table.Th><Table.Th>{t('Name')}</Table.Th><Table.Th>{t('Destinations')}</Table.Th><Table.Th>{t('Route')}</Table.Th><Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rules.map((r, i) => (
                  <Table.Tr key={i}>
                    <Table.Td c="dimmed">{i + 1}</Table.Td>
                    <Table.Td><Text fw={600}>{r.name}</Text></Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {r.domains.length > 0 && <>{tags(r.domains.map((d) => `*.${d}`))}</>}
                        {r.hosts.length > 0 && <>{tags(r.hosts)}</>}
                        {r.networks.length > 0 && <>{tags(r.networks)}</>}
                      </Group>
                      {(r.exitVpn || r.exitLabel) && (
                        <Group gap={4} mt={6}>
                          <Text size="xs" c="dimmed">{t('only if the exit is')}</Text>
                          {r.exitVpn === 'up' && <Badge size="xs" variant="light" color="grape" tt="none">{t('on a VPN')}</Badge>}
                          {r.exitVpn === 'down' && <Badge size="xs" variant="light" color="gray" tt="none">{t('not on a VPN')}</Badge>}
                          {r.exitLabel && <Badge size="xs" variant="outline" color="grape" tt="none">{r.exitLabel}</Badge>}
                        </Group>
                      )}
                    </Table.Td>
                    <Table.Td><Badge variant="light" radius="sm" tt="none" size="md">{r.route}</Badge></Table.Td>
                    <Table.Td>
                      <Group gap={2} justify="flex-end" wrap="nowrap">
                        <ActionIcon variant="subtle" color="gray" disabled={i === 0} onClick={() => move(i, -1)} aria-label={t('Move up')} title={t('Move up')}><IconArrowUp size={16} /></ActionIcon>
                        <ActionIcon variant="subtle" color="gray" disabled={i === rules.length - 1} onClick={() => move(i, 1)} aria-label={t('Move down')} title={t('Move down')}><IconArrowDown size={16} /></ActionIcon>
                        <ActionIcon variant="subtle" onClick={() => { setEditIdx(i); setForm({ ...r }); open() }} aria-label={t('Edit')} title={t('Edit')}><IconPencil size={16} /></ActionIcon>
                        <ActionIcon variant="subtle" color="red" aria-label={t('Delete')} title={t('Delete')}
                          onClick={() => window.confirm(t('Delete the rule "{{name}}"?', { name: r.name })) && persist(rules.filter((_, j) => j !== i))}>
                          <IconTrash size={16} />
                        </ActionIcon>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>

      <Modal opened={opened} onClose={close} title={editIdx === null ? t('New rule') : t('Edit rule')} centered size="lg">
        <Stack gap="sm">
          <TextInput label={t('Name')} value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
          <TagsInput label={t('Domains (including subdomains)')} placeholder={t('example.com, corp.local — Press Enter to add')}
            value={form.domains} onChange={(v) => setForm({ ...form, domains: v })} />
          <TagsInput label={t('Exact hosts')} placeholder="intranet.example.com"
            value={form.hosts} onChange={(v) => setForm({ ...form, hosts: v })} />
          <TagsInput label={t('IPs or CIDR networks')} placeholder="10.0.0.0/8, 192.168.1.5"
            value={form.networks} onChange={(v) => setForm({ ...form, networks: v })} />
          <Select label={t('Route')} data={routeOptions} value={form.route || null}
            onChange={(v) => setForm({ ...form, route: v ?? '' })} />
          <Text size="sm" fw={600} mt="xs">{t('Only if the relay exit is...')}</Text>
          <Text size="xs" c="dimmed" mt={-8}>
            {t('Optional. Applies to routes with a relay hop: the rule is skipped, and the next one is tried, when the exit does not match what its owner shares (VPN yes/no and a network label).')}
          </Text>
          <Group grow align="flex-start">
            <Select label={t('VPN')} placeholder={t('Any')} clearable
              data={[{ value: 'up', label: t('Exit on a VPN') }, { value: 'down', label: t('Exit not on a VPN') }]}
              value={form.exitVpn || null} onChange={(v) => setForm({ ...form, exitVpn: v ?? '' })} />
            <TextInput label={t('Network label')} placeholder="office*, home"
              value={form.exitLabel ?? ''} onChange={(e) => setForm({ ...form, exitLabel: e.currentTarget.value })} />
          </Group>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>{t('Cancel')}</Button>
            <Button onClick={save}
              disabled={!form.name || !form.route || form.domains.length + form.hosts.length + form.networks.length === 0}>
              {t('Save')}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  )
}
