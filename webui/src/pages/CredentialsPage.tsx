import { useCallback, useEffect, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Button, Card, Group, Modal, PasswordInput, Stack, Table, Text, TextInput,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconKey, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'
import type { Credential } from '../api'
import { EmptyState, PageHeader } from '../components/ui'

export default function CredentialsPage() {
  const { t } = useTranslation()
  const [creds, setCreds] = useState<Credential[]>([])
  const [opened, { open, close }] = useDisclosure(false)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState<Credential | null>(null)
  const [form, setForm] = useState({ name: '', user: '', password: '' })
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => api.credentials().then(setCreds).catch((e) => setError(String(e))), [])
  useEffect(() => {
    load()
  }, [load])

  const openNew = () => {
    setEditing(null)
    setForm({ name: '', user: '', password: '' })
    open()
  }

  const openEdit = (c: Credential) => {
    setEditing(c)
    // The API never sends the password back: an empty field keeps the current one.
    setForm({ name: c.name, user: c.user, password: '' })
    open()
  }

  const save = async () => {
    setBusy(true)
    try {
      await api.saveCredential(form)
      close()
      await load()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (name: string) => {
    if (!window.confirm(t('Delete the credential "{{name}}"?', { name }))) return
    try {
      await api.deleteCredential(name)
      await load()
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <>
      <PageHeader
        icon={IconKey}
        title={t('Credentials')}
        description={t('Named logins for corporate proxies. Passwords are stored encrypted and are never shown again.')}
        actions={<Button leftSection={<IconPlus size={16} />} onClick={openNew}>{t('Add')}</Button>}
      />

      {error && <Alert color="red" mb="md" withCloseButton onClose={() => setError(null)}>{t('Error:')} {error}</Alert>}

      <Card withBorder padding={0}>
        {!creds.length ? (
          <EmptyState
            icon={IconKey}
            title={t('No credentials')}
            text={t('Add the user and password of your corporate proxy, then pick them in a route hop.')}
            action={<Button mt="xs" leftSection={<IconPlus size={16} />} onClick={openNew}>{t('Add')}</Button>}
          />
        ) : (
          <Table.ScrollContainer minWidth={520}>
            <Table highlightOnHover style={{ border: 0, borderRadius: 0 }}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('Name')}</Table.Th>
                  <Table.Th>{t('User')}</Table.Th>
                  <Table.Th>{t('Password')}</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {creds.map((c) => (
                  <Table.Tr key={c.name}>
                    <Table.Td><Text fw={600}>{c.name}</Text></Table.Td>
                    <Table.Td>{c.user}</Table.Td>
                    <Table.Td>
                      {c.hasPassword
                        ? <Badge variant="light" color="teal" radius="sm">{t('stored')}</Badge>
                        : <Badge variant="light" color="gray" radius="sm">{t('none')}</Badge>}
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end" wrap="nowrap">
                        <ActionIcon variant="subtle" onClick={() => openEdit(c)} title={t('Edit')} aria-label={t('Edit')}>
                          <IconPencil size={16} />
                        </ActionIcon>
                        <ActionIcon variant="subtle" color="red" onClick={() => remove(c.name)} title={t('Delete')} aria-label={t('Delete')}>
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

      <Modal opened={opened} onClose={close} title={editing ? t('Edit {{name}}', { name: editing.name }) : t('New credential')} centered>
        <Stack gap="sm">
          <TextInput
            label={t('Name')}
            placeholder={t('e.g. Company')}
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.currentTarget.value })}
          />
          <TextInput
            label={t('User')}
            placeholder={t('username or DOMAIN\\username')}
            value={form.user}
            onChange={(e) => setForm({ ...form, user: e.currentTarget.value })}
          />
          <PasswordInput
            label={t('Password')}
            description={editing ? t('Leave empty to keep the current password') : undefined}
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.currentTarget.value })}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>{t('Cancel')}</Button>
            <Button onClick={save} loading={busy} disabled={!form.name}>{t('Save')}</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}
