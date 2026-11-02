import { useCallback, useEffect, useState } from 'react'
import {
  ActionIcon, Alert, Button, Group, Modal, PasswordInput, Stack, Table, Text, TextInput, Title,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconPencil, IconPlus, IconTrash } from '@tabler/icons-react'
import { api } from '../api'
import type { Credential } from '../api'

export default function CredentialsPage() {
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
    if (!window.confirm(`Eliminare la credenziale "${name}"?`)) return
    try {
      await api.deleteCredential(name)
      await load()
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={3}>Credenziali</Title>
        <Button leftSection={<IconPlus size={16} />} onClick={openNew}>Aggiungi</Button>
      </Group>

      {error && <Alert color="red" mb="md">Errore: {error}</Alert>}

      <Table striped highlightOnHover withTableBorder>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Nome</Table.Th>
            <Table.Th>Utente</Table.Th>
            <Table.Th>Password</Table.Th>
            <Table.Th />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {creds.map((c) => (
            <Table.Tr key={c.name}>
              <Table.Td><Text fw={600}>{c.name}</Text></Table.Td>
              <Table.Td>{c.user}</Table.Td>
              <Table.Td>
                <Text c="dimmed">{c.hasPassword ? '••••••••' : 'nessuna'}</Text>
              </Table.Td>
              <Table.Td>
                <Group gap="xs" justify="flex-end">
                  <ActionIcon variant="subtle" color="blue" onClick={() => openEdit(c)} title="Modifica">
                    <IconPencil size={16} />
                  </ActionIcon>
                  <ActionIcon variant="subtle" color="red" onClick={() => remove(c.name)} title="Elimina">
                    <IconTrash size={16} />
                  </ActionIcon>
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>

      <Modal opened={opened} onClose={close} title={editing ? `Modifica ${editing.name}` : 'Nuova credenziale'} centered>
        <Stack gap="sm">
          <TextInput
            label="Nome"
            placeholder="es. Azienda"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.currentTarget.value })}
          />
          <TextInput
            label="Utente"
            placeholder="username oppure DOMAIN\\username"
            value={form.user}
            onChange={(e) => setForm({ ...form, user: e.currentTarget.value })}
          />
          <PasswordInput
            label="Password"
            description={editing ? 'Lascia vuoto per mantenere la password attuale' : undefined}
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.currentTarget.value })}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>Annulla</Button>
            <Button onClick={save} loading={busy} disabled={!form.name}>Salva</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}
