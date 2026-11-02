import { useCallback, useEffect, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Button, Card, Code, Group, Modal, Select, Stack, Table, TagsInput, Text, TextInput, Title,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconArrowDown, IconArrowUp, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react'
import { api } from '../api'
import type { RoutingRule, RuleTest } from '../api'

const empty: RoutingRule = { name: '', domains: [], hosts: [], networks: [], route: '' }

// The backend may send null for empty lists (older versions, or hand-edited
// config.yml): normalize them so the page can always use .length and .map.
const normalize = (r: RoutingRule): RoutingRule => ({
  ...r,
  domains: r.domains ?? [],
  hosts: r.hosts ?? [],
  networks: r.networks ?? [],
})

export default function RulesPage() {
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

  const tags = (v: string[]) => v.map((x) => <Badge key={x} variant="light" size="sm" mr={4}>{x}</Badge>)

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={3}>Regole per destinazione</Title>
        <Button leftSection={<IconPlus size={16} />} onClick={() => { setEditIdx(null); setForm(empty); open() }}>
          Nuova regola
        </Button>
      </Group>
      <Text size="sm" c="dimmed">
        Le regole sono valutate solo con selezione <b>Auto</b> (o esplicitamente da un salto <b>Dinamico</b>), in
        ordine: vince la prima che corrisponde e la cui route è applicabile sulla rete corrente. Se nessuna
        corrisponde si usa la selezione normale. Una route forzata ha la precedenza e disattiva le regole.
      </Text>
      {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}

      <Card withBorder>
        <Text fw={700} mb="xs">Verifica una destinazione</Text>
        <Group gap="xs" align="flex-end">
          <TextInput placeholder="www.example.com oppure 10.1.2.3" value={testHost} w={320}
            onChange={(e) => setTestHost(e.currentTarget.value)}
            onKeyDown={(e) => e.key === 'Enter' && testHost.trim() && test()} />
          <Button variant="light" onClick={test} disabled={!testHost.trim()}>Verifica</Button>
        </Group>
        {testRes && (
          <Text size="sm" mt="xs">
            {testRes.ip && <>IP <Code>{testRes.ip}</Code> · </>}
            route <b>{testRes.route ?? 'nessuna'}</b>
            {testRes.rule ? <> (regola <b>{testRes.rule}</b>)</> : ' (selezione normale)'}
          </Text>
        )}
      </Card>

      <Table withTableBorder striped>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>#</Table.Th><Table.Th>Nome</Table.Th><Table.Th>Destinazioni</Table.Th><Table.Th>Route</Table.Th><Table.Th />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rules.map((r, i) => (
            <Table.Tr key={i}>
              <Table.Td>{i + 1}</Table.Td>
              <Table.Td>{r.name}</Table.Td>
              <Table.Td>
                <Group gap={4}>
                  {r.domains.length > 0 && <>{tags(r.domains.map((d) => `*.${d}`))}</>}
                  {r.hosts.length > 0 && <>{tags(r.hosts)}</>}
                  {r.networks.length > 0 && <>{tags(r.networks)}</>}
                </Group>
              </Table.Td>
              <Table.Td><Badge>{r.route}</Badge></Table.Td>
              <Table.Td>
                <Group gap={2} justify="flex-end" wrap="nowrap">
                  <ActionIcon variant="subtle" color="gray" disabled={i === 0} onClick={() => move(i, -1)}><IconArrowUp size={16} /></ActionIcon>
                  <ActionIcon variant="subtle" color="gray" disabled={i === rules.length - 1} onClick={() => move(i, 1)}><IconArrowDown size={16} /></ActionIcon>
                  <ActionIcon variant="subtle" onClick={() => { setEditIdx(i); setForm({ ...r }); open() }}><IconPencil size={16} /></ActionIcon>
                  <ActionIcon variant="subtle" color="red"
                    onClick={() => window.confirm(`Eliminare la regola "${r.name}"?`) && persist(rules.filter((_, j) => j !== i))}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
      {!rules.length && <Text c="dimmed" size="sm">Nessuna regola</Text>}

      <Modal opened={opened} onClose={close} title={editIdx === null ? 'Nuova regola' : 'Modifica regola'} centered size="lg">
        <Stack gap="sm">
          <TextInput label="Nome" value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
          <TagsInput label="Domini (compresi i sottodomini)" placeholder="example.com, corp.local — Invio per aggiungere"
            value={form.domains} onChange={(v) => setForm({ ...form, domains: v })} />
          <TagsInput label="Host esatti" placeholder="intranet.example.com"
            value={form.hosts} onChange={(v) => setForm({ ...form, hosts: v })} />
          <TagsInput label="IP o reti CIDR" placeholder="10.0.0.0/8, 192.168.1.5"
            value={form.networks} onChange={(v) => setForm({ ...form, networks: v })} />
          <Select label="Route" data={routeOptions} value={form.route || null}
            onChange={(v) => setForm({ ...form, route: v ?? '' })} />
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>Annulla</Button>
            <Button onClick={save}
              disabled={!form.name || !form.route || form.domains.length + form.hosts.length + form.networks.length === 0}>
              Salva
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  )
}
