import { useCallback, useEffect, useState } from 'react'
import {
  ActionIcon, Alert, Badge, Button, Card, Code, Group, Stack, Table, Text, TextInput, Title,
} from '@mantine/core'
import { IconCheck, IconPlus, IconTrash, IconX } from '@tabler/icons-react'
import { api } from '../api'
import type { RelayStatus } from '../api'

export default function RelayPage() {
  const [st, setSt] = useState<RelayStatus | null>(null)
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    api.relay().then(setSt).catch((e) => setError(String(e)))
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 2000)
    return () => clearInterval(t)
  }, [load])

  const run = async (fn: () => Promise<unknown>) => {
    try {
      setError(null)
      await fn()
      load()
    } catch (e) {
      setError(String(e))
    }
  }

  if (!st) return null
  if (!st.enabled) {
    return (
      <>
        <Title order={3} mb="md">Relay</Title>
        <Alert color="gray">
          Nessun relay configurato. Aggiungi la sezione <Code>Relay</Code> in config.yml
          (Address, Cert, Key, CA) e riavvia il proxy.
        </Alert>
      </>
    )
  }

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={3}>Relay</Title>
        <Group gap="xs">
          <Badge color={st.connected ? 'green' : 'red'} variant="light">
            {st.connected ? 'connesso' : 'non connesso'}
          </Badge>
          <Code>{st.address}</Code>
          {st.email && <Badge variant="outline" color="gray">{st.email}</Badge>}
          {st.connected && st.route && <Badge variant="outline" color="gray">via {st.route}</Badge>}
        </Group>
      </Group>

      {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}
      {st.notice && <Alert color="yellow">{st.notice}</Alert>}
      {!st.connected && st.error && <Alert color="red" title="Connessione al relay">{st.error}</Alert>}

      {st.approvals.length > 0 && (
        <Card withBorder>
          <Text fw={700} mb="xs">Richieste di rotta da approvare</Text>
          <Text size="xs" c="dimmed" mb="xs">
            Un contatto vuole uscire dalla tua rete verso questa destinazione. Scade dopo 60 secondi.
          </Text>
          <Table>
            <Table.Tbody>
              {st.approvals.map((a) => (
                <Table.Tr key={a.id}>
                  <Table.Td><b>{a.from}</b></Table.Td>
                  <Table.Td><Code>{a.host}:{a.port}</Code></Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end">
                      <Button size="xs" variant="default" onClick={() => run(() => api.relayDecide(a.id, { allow: true }))}>
                        Consenti una volta
                      </Button>
                      <Button size="xs" onClick={() => run(() => api.relayDecide(a.id, { allow: true, always: true }))}>
                        Consenti sempre
                      </Button>
                      <Button size="xs" variant="light" onClick={() => run(() => api.relayDecide(a.id, { allow: true, always: true, anyPort: true }))}>
                        Sempre, tutte le porte
                      </Button>
                      <Button size="xs" color="red" variant="light" onClick={() => run(() => api.relayDecide(a.id, { allow: false }))}>
                        Nega
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}

      {st.incoming.length > 0 && (
        <Card withBorder>
          <Text fw={700} mb="xs">Richieste di contatto</Text>
          <Table>
            <Table.Tbody>
              {st.incoming.map((e) => (
                <Table.Tr key={e}>
                  <Table.Td>{e}</Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end">
                      <Button size="xs" leftSection={<IconCheck size={14} />} onClick={() => run(() => api.relayRespond(e, true))}>
                        Accetta
                      </Button>
                      <Button size="xs" color="red" variant="light" leftSection={<IconX size={14} />} onClick={() => run(() => api.relayRespond(e, false))}>
                        Rifiuta
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}

      <Card withBorder>
        <Group justify="space-between" mb="xs">
          <Text fw={700}>Rubrica</Text>
          <form
            onSubmit={(ev) => {
              ev.preventDefault()
              if (!email.trim()) return
              run(() => api.relayRequest(email.trim())).then(() => setEmail(''))
            }}
          >
            <Group gap="xs">
              <TextInput size="xs" placeholder="indirizzo e-mail del contatto" value={email}
                onChange={(e) => setEmail(e.currentTarget.value)} w={280} />
              <Button size="xs" type="submit" leftSection={<IconPlus size={14} />} disabled={!st.connected}>
                Invia richiesta
              </Button>
            </Group>
          </form>
        </Group>
        <Table>
          <Table.Tbody>
            {st.contacts.map((c) => (
              <Table.Tr key={c.email}>
                <Table.Td>{c.email}</Table.Td>
                <Table.Td><Badge size="sm" variant="light" color={c.online ? 'green' : 'gray'}>{c.online ? 'online' : 'offline'}</Badge></Table.Td>
                <Table.Td><Code>relay://{c.email}</Code></Table.Td>
                <Table.Td>
                  <ActionIcon variant="subtle" color="red" title="Rimuovi contatto"
                    onClick={() => window.confirm(`Rimuovere ${c.email}?`) && run(() => api.relayRemove(c.email))}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
            {st.outgoing.map((e) => (
              <Table.Tr key={e}>
                <Table.Td>{e}</Table.Td>
                <Table.Td><Badge size="sm" variant="light" color="yellow">in attesa</Badge></Table.Td>
                <Table.Td />
                <Table.Td>
                  <ActionIcon variant="subtle" color="gray" title="Annulla richiesta" onClick={() => run(() => api.relayRemove(e))}>
                    <IconX size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!st.contacts.length && !st.outgoing.length && <Text c="dimmed" size="sm">Nessun contatto</Text>}
        <Text size="xs" c="dimmed" mt="xs">
          Per uscire dalla rete di un contatto usa <Code>relay://email</Code> come primo proxy della catena di una route.
        </Text>
      </Card>

      <Card withBorder>
        <Text fw={700} mb="xs">Rotte approvate (chi può uscire dalla tua rete)</Text>
        <Table>
          <Table.Tbody>
            {st.rules.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>{r.from}</Table.Td>
                <Table.Td><Code>{r.host}:{r.port || '*'}</Code></Table.Td>
                <Table.Td>
                  <ActionIcon variant="subtle" color="red" title="Revoca" onClick={() => run(() => api.relayDeleteRule(r.id))}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!st.rules.length && <Text c="dimmed" size="sm">Nessuna rotta approvata</Text>}
      </Card>
    </Stack>
  )
}
