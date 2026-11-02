import { useState } from 'react'
import { Alert, Badge, Button, Card, Center, Code, Container, Group, Stack, Text, Title } from '@mantine/core'
import { IconArrowRight, IconCheck } from '@tabler/icons-react'
import { api } from '../api'
import type { StateInfo } from '../api'

export default function OnboardingPage({ state }: { state: StateInfo }) {
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const start = async () => {
    setBusy(true)
    try {
      await api.finishOnboarding()
      window.location.reload()
    } catch (e) {
      setError(String(e))
      setBusy(false)
    }
  }

  return (
    <Center mih="100vh" bg="var(--mantine-color-body)" p="md">
      <Container>
        <Card withBorder shadow="sm" p="xl" maw={640}>
          <Stack gap="md">
            <Group gap="xs">
              <IconCheck size={28} color="var(--mantine-color-green-6)" />
              <Title order={2}>Go Smart Proxy è pronto</Title>
            </Group>
            <Text size="sm" c="dimmed">
              La configurazione è cifrata con la master password scelta nel setup. I listener
              predefiniti sono già attivi e il proxy è utilizzabile subito.
            </Text>

            {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}

            <Card withBorder>
              <Stack gap="xs">
                <Group justify="space-between">
                  <Text fw={600}>Proxy HTTP e web UI</Text>
                  <Badge variant="light">{state.address}</Badge>
                </Group>
                {state.socksAddress && (
                  <Group justify="space-between">
                    <Text fw={600}>Proxy SOCKS5</Text>
                    <Badge variant="light" color="grape">{state.socksAddress}</Badge>
                  </Group>
                )}
                <Text size="xs" c="dimmed">
                  Punta le applicazioni su uno di questi indirizzi. I listener sono solo su
                  loopback; puoi cambiarli da Configurazione.
                </Text>
              </Stack>
            </Card>

            <Text size="sm">
              Dalla web app puoi ora configurare:
            </Text>
            <Stack gap={4}>
              <Text size="sm">• <b>Regole</b> — destinazioni e route dedicate</Text>
              <Text size="sm">• <b>Credenziali</b> — proxy aziendali e autenticazione</Text>
              <Text size="sm">• <b>Configurazione</b> — listener, proxy di sistema, PAC</Text>
              <Text size="sm">• <b>Relay</b> — collega questo dispositivo ai tuoi contatti</Text>
            </Stack>

            <Group justify="flex-end">
              <Button rightSection={<IconArrowRight size={16} />} loading={busy} onClick={start}>
                Inizia a usare il proxy
              </Button>
            </Group>

            <Text size="xs" c="dimmed">
              Esempio: <Code>curl -x {state.address} https://example.com</Code>
            </Text>
          </Stack>
        </Card>
      </Container>
    </Center>
  )
}
