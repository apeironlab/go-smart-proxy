import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ActionIcon, Alert, Badge, Button, Group, Modal, Select, Stack, Switch, Table, TagsInput, Text, TextInput, Tooltip,
} from '@mantine/core'
import { IconPencil, IconPlus, IconRefresh, IconShieldOff, IconTrash } from '@tabler/icons-react'
import { EmptyState, PageHeader, Section } from '../../src/components/ui'
import { adminApi } from '../api'
import type { PolicyConfig, PolicyList, PolicyRule } from '../api'
import { fmtDate } from '../format'
import { message, usePolling } from '../hooks'

export default function PolicyPage() {
  const { t } = useTranslation()
  const { data, error, reload } = usePolling(adminApi.policy, 5000)
  const [problem, setProblem] = useState<string | null>(null)
  const [rule, setRule] = useState<PolicyRule | 'new' | null>(null)
  const [list, setList] = useState<PolicyList | 'new' | null>(null)
  const [busy, setBusy] = useState(false)

  const cfg: PolicyConfig = data?.config ?? { rules: [], lists: [], allow: [] }
  const readOnly = !!data?.readOnly

  const save = async (next: PolicyConfig) => {
    try {
      await adminApi.savePolicy(next)
      setProblem(null)
      reload()
      return true
    } catch (e) {
      setProblem(message(e))
      return false
    }
  }

  const kind = (m?: boolean) => (m
    ? <Badge color="orange" variant="light" tt="none">{t('required')}</Badge>
    : <Badge color="gray" variant="light" tt="none">{t('recommended')}</Badge>)

  return (
    <>
      <PageHeader
        icon={IconShieldOff} title={t('Blocking')}
        description={t('Hosts the organization does not want reached: rules and downloaded lists (hosts files, domain lists, adblock lists). Required ones are enforced here, on connections through the relay, and by every proxy, which cannot switch them off. Recommended ones are offered to the proxies, whose users may turn them off.')}
        actions={data?.enabled ? (
          <Button
            variant="default" leftSection={<IconRefresh size={16} />} loading={busy}
            onClick={() => { setBusy(true); void adminApi.refreshPolicy().then(reload).catch((e: unknown) => setProblem(message(e))).finally(() => setBusy(false)) }}
          >{t('Update lists')}</Button>
        ) : undefined}
      />
      {(problem || error) && <Alert color="red" variant="light" mb="md">{problem ?? error}</Alert>}
      {data && !data.enabled && <Alert color="yellow" variant="light" mb="md">{t('Blocking is not enabled on this relay: start it with -policy or with the management database.')}</Alert>}
      {readOnly && <Alert color="blue" variant="light" mb="md">{t('The policy is read from a file on the relay. Edit that file to change it.')}</Alert>}

      {data?.enabled && (
        <>
          <Section
            title={t('Rules')} description={t('Hosts written by hand. A domain blocks its subdomains too; an address or a network blocks what is in it.')}
            right={!readOnly ? <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => setRule('new')}>{t('Add rule')}</Button> : undefined}
          >
            {cfg.rules.length === 0 ? <EmptyState icon={IconShieldOff} title={t('No rules')} /> : (
              <Table.ScrollContainer minWidth={560}>
                <Table highlightOnHover>
                  <Table.Tbody>
                    {cfg.rules.map((r) => (
                      <Table.Tr key={r.id} opacity={r.disabled ? 0.5 : 1}>
                        <Table.Td><Text size="sm" fw={600}>{r.name}</Text><Text size="xs" c="dimmed">{[...(r.domains ?? []), ...(r.nets ?? [])].slice(0, 4).join(', ')}{(r.domains?.length ?? 0) + (r.nets?.length ?? 0) > 4 ? '…' : ''}</Text></Table.Td>
                        <Table.Td>{kind(r.mandatory)}</Table.Td>
                        <Table.Td>{(data.counts[r.name] ?? 0) > 0 && <Text size="xs" c="dimmed">{t('{{count}} refused', { count: data.counts[r.name] })}</Text>}</Table.Td>
                        <Table.Td>
                          {!readOnly && (
                            <Group gap={4} justify="flex-end" wrap="nowrap">
                              <Tooltip label={t('Edit')}><ActionIcon variant="subtle" aria-label={t('Edit')} onClick={() => setRule(r)}><IconPencil size={16} /></ActionIcon></Tooltip>
                              <Tooltip label={t('Delete')}>
                                <ActionIcon variant="subtle" color="red" aria-label={t('Delete')} onClick={() => { if (window.confirm(t('Delete {{name}}?', { name: r.name }))) void save({ ...cfg, rules: cfg.rules.filter((x) => x.id !== r.id) }) }}><IconTrash size={16} /></ActionIcon>
                              </Tooltip>
                            </Group>
                          )}
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
          </Section>

          <Section
            title={t('Lists')} description={t('Downloaded by the relay and, to be applied by the proxies, by each of them.')}
            right={!readOnly ? <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => setList('new')}>{t('Add list')}</Button> : undefined}
          >
            {cfg.lists.length === 0 ? <EmptyState icon={IconShieldOff} title={t('No lists')} /> : (
              <Table.ScrollContainer minWidth={620}>
                <Table highlightOnHover>
                  <Table.Tbody>
                    {cfg.lists.map((l) => {
                      const st = data.lists.find((x) => x.id === l.id)
                      return (
                        <Table.Tr key={l.id} opacity={l.disabled ? 0.5 : 1}>
                          <Table.Td>
                            <Text size="sm" fw={600}>{l.name}</Text>
                            <Text size="xs" c="dimmed" style={{ wordBreak: 'break-all' }}>{l.url}</Text>
                          </Table.Td>
                          <Table.Td>{kind(l.mandatory)}</Table.Td>
                          <Table.Td>
                            {st && (st.error
                              ? <Text size="xs" c="red">{st.error}</Text>
                              : <Text size="xs" c="dimmed">{t('{{count}} entries · {{date}}', { count: st.entries, date: fmtDate(st.fetched) })}</Text>)}
                            {(data.counts[l.name] ?? 0) > 0 && <Text size="xs" c="dimmed">{t('{{count}} refused', { count: data.counts[l.name] })}</Text>}
                          </Table.Td>
                          <Table.Td>
                            {!readOnly && (
                              <Group gap={4} justify="flex-end" wrap="nowrap">
                                <Tooltip label={t('Edit')}><ActionIcon variant="subtle" aria-label={t('Edit')} onClick={() => setList(l)}><IconPencil size={16} /></ActionIcon></Tooltip>
                                <Tooltip label={t('Delete')}>
                                  <ActionIcon variant="subtle" color="red" aria-label={t('Delete')} onClick={() => { if (window.confirm(t('Delete {{name}}?', { name: l.name }))) void save({ ...cfg, lists: cfg.lists.filter((x) => x.id !== l.id) }) }}><IconTrash size={16} /></ActionIcon>
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

          <Section title={t('Exceptions')} description={t('Domains the relay\'s rules never block: the fix for a list that blocks something it should not.')}>
            <TagsInput
              value={cfg.allow} disabled={readOnly} placeholder="example.com"
              onChange={(v) => { void save({ ...cfg, allow: v }) }}
            />
          </Section>

          <Section title={t('Refused by the relay')} description={t('Connections through the relay that a required rule refused.')}>
            {data.recent.length === 0 ? <Text size="sm" c="dimmed">{t('Nothing refused yet.')}</Text> : (
              <Table verticalSpacing="xs">
                <Table.Tbody>
                  {data.recent.slice(0, 15).map((e, i) => (
                    <Table.Tr key={i}>
                      <Table.Td w={170}><Text size="xs" c="dimmed">{fmtDate(e.time)}</Text></Table.Td>
                      <Table.Td><Text size="sm">{e.email}</Text></Table.Td>
                      <Table.Td><Text size="sm" ff="monospace">{e.host}</Text></Table.Td>
                      <Table.Td><Text size="xs" c="dimmed">{e.source}</Text></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
          </Section>
        </>
      )}

      {rule && (
        <RuleModal
          rule={rule === 'new' ? null : rule} taken={[...cfg.rules.map((r) => r.id), ...cfg.lists.map((l) => l.id)]}
          onClose={() => setRule(null)}
          onSave={async (r) => {
            const next = rule === 'new' ? [...cfg.rules, r] : cfg.rules.map((x) => (x.id === r.id ? r : x))
            if (await save({ ...cfg, rules: next })) setRule(null)
          }}
        />
      )}
      {list && (
        <ListModal
          list={list === 'new' ? null : list} taken={[...cfg.rules.map((r) => r.id), ...cfg.lists.map((l) => l.id)]}
          onClose={() => setList(null)}
          onSave={async (l) => {
            const next = list === 'new' ? [...cfg.lists, l] : cfg.lists.map((x) => (x.id === l.id ? l : x))
            if (await save({ ...cfg, lists: next })) setList(null)
          }}
        />
      )}
    </>
  )
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 28)

function uniqueId(base: string, taken: string[]) {
  let id = slug(base) || 'item'
  let n = 2
  while (taken.includes(id)) id = `${slug(base).slice(0, 24) || 'item'}-${n++}`
  return id
}

function RuleModal({ rule, taken, onClose, onSave }: { rule: PolicyRule | null; taken: string[]; onClose: () => void; onSave: (r: PolicyRule) => Promise<void> }) {
  const { t } = useTranslation()
  const [name, setName] = useState(rule?.name ?? '')
  const [domains, setDomains] = useState<string[]>(rule?.domains ?? [])
  const [nets, setNets] = useState<string[]>(rule?.nets ?? [])
  const [mandatory, setMandatory] = useState(rule?.mandatory ?? true)
  const [disabled, setDisabled] = useState(rule?.disabled ?? false)
  const [busy, setBusy] = useState(false)
  return (
    <Modal opened onClose={onClose} title={rule ? t('Edit {{name}}', { name: rule.name }) : t('Add rule')} size="lg">
      <form onSubmit={(e) => {
        e.preventDefault()
        setBusy(true)
        void onSave({
          id: rule?.id ?? uniqueId(name, taken), name: name.trim(), mandatory: mandatory || undefined,
          domains: domains.length ? domains : undefined, nets: nets.length ? nets : undefined, disabled: disabled || undefined,
        }).finally(() => setBusy(false))
      }}>
        <Stack gap="sm">
          <TextInput label={t('Name')} value={name} onChange={(e) => setName(e.currentTarget.value)} required autoFocus />
          <TagsInput label={t('Domains')} value={domains} onChange={setDomains} placeholder="social.example.com" description={t('A domain blocks its subdomains too.')} />
          <TagsInput label={t('Addresses and networks')} value={nets} onChange={setNets} placeholder="203.0.113.0/24" />
          <Switch checked={mandatory} onChange={(e) => setMandatory(e.currentTarget.checked)} label={t('Required: users cannot switch it off')} />
          <Switch checked={disabled} onChange={(e) => setDisabled(e.currentTarget.checked)} label={t('Switched off')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>{t('Cancel')}</Button>
            <Button type="submit" loading={busy} disabled={!domains.length && !nets.length}>{t('Save')}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}

function ListModal({ list, taken, onClose, onSave }: { list: PolicyList | null; taken: string[]; onClose: () => void; onSave: (l: PolicyList) => Promise<void> }) {
  const { t } = useTranslation()
  const [name, setName] = useState(list?.name ?? '')
  const [url, setUrl] = useState(list?.url ?? '')
  const [format, setFormat] = useState(list?.format || 'auto')
  const [mandatory, setMandatory] = useState(list?.mandatory ?? false)
  const [disabled, setDisabled] = useState(list?.disabled ?? false)
  const [busy, setBusy] = useState(false)
  return (
    <Modal opened onClose={onClose} title={list ? t('Edit {{name}}', { name: list.name }) : t('Add list')} size="lg">
      <form onSubmit={(e) => {
        e.preventDefault()
        setBusy(true)
        void onSave({
          id: list?.id ?? uniqueId(name, taken), name: name.trim(), url: url.trim(), format, mandatory: mandatory || undefined, disabled: disabled || undefined,
        }).finally(() => setBusy(false))
      }}>
        <Stack gap="sm">
          <TextInput label={t('Name')} value={name} onChange={(e) => setName(e.currentTarget.value)} required autoFocus />
          <TextInput label={t('Address')} placeholder="https://example.com/hosts.txt" value={url} onChange={(e) => setUrl(e.currentTarget.value)} required />
          <Select
            label={t('Format')} value={format} allowDeselect={false} onChange={(v) => setFormat(v ?? 'auto')}
            data={[{ value: 'auto', label: t('Detect') }, { value: 'hosts', label: t('Hosts file') }, { value: 'domains', label: t('One domain per line') }, { value: 'abp', label: t('Adblock (||domain^)') }]}
          />
          <Switch checked={mandatory} onChange={(e) => setMandatory(e.currentTarget.checked)} label={t('Required: users cannot switch it off')} />
          <Switch checked={disabled} onChange={(e) => setDisabled(e.currentTarget.checked)} label={t('Switched off')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>{t('Cancel')}</Button>
            <Button type="submit" loading={busy}>{t('Save')}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
