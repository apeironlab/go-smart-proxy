import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert, Badge, Button, Divider, Group, NumberInput, PasswordInput, Select, SimpleGrid, Stack, Switch, TagsInput, Text, TextInput } from '@mantine/core'
import { IconCheck, IconShieldLock } from '@tabler/icons-react'
import { PageHeader, Section } from '../../src/components/ui'
import { adminApi } from '../api'
import type { Rules } from '../api'
import { message, usePolling } from '../hooks'

interface MethodForm {
  id: string
  type: string
  label: string
  disabled: boolean
  groups: string[]
  defaultGroups: string[]
}

export default function AccessPage() {
  const { t } = useTranslation()
  const { data, error } = usePolling(adminApi.rules, 0)
  const [domains, setDomains] = useState<string[]>([])
  const [days, setDays] = useState<number | string>(90)
  const [methods, setMethods] = useState<MethodForm[]>([])
  const [smtp, setSmtp] = useState({ addr: '', user: '', from: '', tls: 'starttls', auth: 'auto' })
  const [pass, setPass] = useState('')
  const [clearPass, setClearPass] = useState(false)
  const [hasPass, setHasPass] = useState(false)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const load = (r: Rules) => {
    setDomains(r.allowedDomains)
    setDays(Math.max(1, Math.round(r.certTtlHours / 24)))
    setMethods(r.methods.map((m) => ({ ...m })))
    setSmtp({ addr: r.smtp.addr, user: r.smtp.user, from: r.smtp.from, tls: r.smtp.tls || 'starttls', auth: r.smtp.auth || 'auto' })
    setHasPass(r.smtp.hasPass)
    setPass('')
    setClearPass(false)
  }
  useEffect(() => { if (data) load(data) }, [data])

  const setMethod = (id: string, patch: Partial<MethodForm>) =>
    setMethods((all) => all.map((m) => (m.id === id ? { ...m, ...patch } : m)))

  const save = async () => {
    setBusy(true)
    setProblem(null)
    setSaved(false)
    try {
      const n = Number(days)
      const r = await adminApi.saveRules({
        allowedDomains: domains,
        certTtlHours: Math.round(n * 24),
        methods: methods.map((m) => ({ id: m.id, disabled: m.disabled, groups: m.groups })),
        smtp: { ...smtp, ...(clearPass ? { pass: '' } : pass ? { pass } : {}) },
      })
      load(r)
      setSaved(true)
    } catch (e) {
      setProblem(message(e))
    } finally {
      setBusy(false)
    }
  }

  const emailOn = !methods.find((m) => m.id === 'email')?.disabled

  return (
    <>
      <PageHeader
        icon={IconShieldLock} title={t('Access and enrollment')}
        description={t('Who can get a certificate, how they prove who they are, and how long it lasts. Changes apply immediately to new requests.')}
        actions={<Button loading={busy} leftSection={<IconCheck size={16} />} onClick={() => { void save() }} disabled={!data}>{t('Save changes')}</Button>}
      />
      {(problem || error) && <Alert color="red" variant="light" mb="md">{problem ?? error}</Alert>}
      {saved && <Alert color="green" variant="light" mb="md" withCloseButton onClose={() => setSaved(false)}>{t('Saved.')}</Alert>}

      <Section title={t('Sign-in methods')} description={t('Switch a method off to stop offering it. Groups limit a method to people whose account (or identity provider) lists one of them; leave empty for everybody.')}>
        <Stack gap="md">
          {methods.map((m, i) => (
            <div key={m.id}>
              {i > 0 && <Divider mb="md" />}
              <Group justify="space-between" align="flex-start" wrap="nowrap" gap="md">
                <div style={{ minWidth: 0 }}>
                  <Group gap="xs">
                    <Text fw={600}>{m.label}</Text>
                    <Badge variant="light" tt="none" color="gray">{m.id === 'email' ? t('e-mail code') : m.type}</Badge>
                  </Group>
                  {m.id !== 'email' && (
                    <TagsInput
                      mt="xs" w={{ base: '100%', sm: 420 }} label={t('Required groups')} disabled={m.disabled}
                      description={m.defaultGroups.length ? t('Configuration file: {{groups}}', { groups: m.defaultGroups.join(', ') }) : t('Configuration file: none')}
                      value={m.groups} onChange={(v) => setMethod(m.id, { groups: v })}
                    />
                  )}
                </div>
                <Switch
                  checked={!m.disabled} onChange={(e) => setMethod(m.id, { disabled: !e.currentTarget.checked })}
                  label={m.disabled ? t('Off') : t('On')} aria-label={m.label}
                />
              </Group>
            </div>
          ))}
        </Stack>
      </Section>

      <Section title={t('Who can enroll')} description={t('Limits that apply whatever the method.')}>
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <TagsInput
            label={t('Allowed e-mail domains')} placeholder="example.com"
            description={t('Empty means every domain. Press Enter to add.')}
            value={domains} onChange={setDomains}
          />
          <NumberInput
            label={t('Certificate lifetime (days)')} description={t('Applies to certificates issued from now on.')}
            min={1} max={1825} value={days} onChange={setDays} allowDecimal={false}
          />
        </SimpleGrid>
      </Section>

      <Section title={t('E-mail (SMTP)')} description={t('Used to send the enrollment code. Only needed while the e-mail code is on.')}>
        {!emailOn && <Alert color="gray" variant="light" mb="md">{t('The e-mail code is off: these settings are not used.')}</Alert>}
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <TextInput label={t('Server')} placeholder="smtp.example.com:587" value={smtp.addr} onChange={(e) => setSmtp({ ...smtp, addr: e.currentTarget.value })} />
          <TextInput label={t('Sender address')} placeholder="relay@example.com" value={smtp.from} onChange={(e) => setSmtp({ ...smtp, from: e.currentTarget.value })} />
          <Select
            label={t('Connection security')} value={smtp.tls} allowDeselect={false}
            data={[{ value: 'starttls', label: 'STARTTLS' }, { value: 'tls', label: 'TLS' }, { value: 'none', label: t('None') }]}
            onChange={(v) => setSmtp({ ...smtp, tls: v ?? 'starttls' })}
          />
          <Select
            label={t('Authentication')} value={smtp.auth} allowDeselect={false}
            data={[{ value: 'auto', label: t('Automatic') }, { value: 'plain', label: 'PLAIN' }, { value: 'login', label: 'LOGIN' }, { value: 'none', label: t('None') }]}
            onChange={(v) => setSmtp({ ...smtp, auth: v ?? 'auto' })}
          />
          <TextInput label={t('User name')} value={smtp.user} onChange={(e) => setSmtp({ ...smtp, user: e.currentTarget.value })} autoComplete="off" />
          <PasswordInput
            label={t('Password')} autoComplete="new-password" value={pass} disabled={clearPass}
            placeholder={hasPass ? t('(unchanged)') : ''}
            description={hasPass ? t('A password is saved. Type a new one to replace it.') : undefined}
            onChange={(e) => setPass(e.currentTarget.value)}
          />
        </SimpleGrid>
        {hasPass && (
          <Switch mt="sm" checked={clearPass} onChange={(e) => setClearPass(e.currentTarget.checked)} label={t('Remove the saved password')} />
        )}
      </Section>

      <Section title={t('Administrators')} description={t('Set in the relay configuration; they cannot be changed from here.')}>
        <Group gap="xs">
          {(data?.admins.groups ?? []).map((g) => <Badge key={'g' + g} variant="light" tt="none">{t('group')}: {g}</Badge>)}
          {(data?.admins.emails ?? []).map((e) => <Badge key={'e' + e} variant="light" color="teal" tt="none">{e}</Badge>)}
        </Group>
      </Section>
    </>
  )
}
