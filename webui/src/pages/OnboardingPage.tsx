import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert, Badge, Button, Card, Center, Code, Container, Group, Stack, Text, Title } from '@mantine/core'
import { IconArrowRight, IconCheck } from '@tabler/icons-react'
import { api } from '../api'
import type { StateInfo } from '../api'

export default function OnboardingPage({ state }: { state: StateInfo }) {
  const { t } = useTranslation()
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
              <Title order={2}>{t('Go Smart Proxy is ready')}</Title>
            </Group>
            <Text size="sm" c="dimmed">
              {t('The configuration is encrypted with the master password chosen during setup. The default listeners are already active and the proxy is ready to use right away.')}
            </Text>

            {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}

            <Card withBorder>
              <Stack gap="xs">
                <Group justify="space-between">
                  <Text fw={600}>{t('HTTP proxy and web UI')}</Text>
                  <Badge variant="light">{state.address}</Badge>
                </Group>
                {state.socksAddress && (
                  <Group justify="space-between">
                    <Text fw={600}>{t('SOCKS5 proxy')}</Text>
                    <Badge variant="light" color="grape">{state.socksAddress}</Badge>
                  </Group>
                )}
                <Text size="xs" c="dimmed">
                  {t('Point your applications at one of these addresses. The listeners are loopback-only; you can change them in Configuration.')}
                </Text>
              </Stack>
            </Card>

            <Text size="sm">
              {t('From the web app you can now configure:')}
            </Text>
            <Stack gap={4}>
              <Text size="sm">• <b>{t('Rules')}</b> — {t('destinations and dedicated routes')}</Text>
              <Text size="sm">• <b>{t('Credentials')}</b> — {t('corporate proxies and authentication')}</Text>
              <Text size="sm">• <b>{t('Configuration')}</b> — {t('listeners, system proxy, PAC')}</Text>
              <Text size="sm">• <b>{t('Relay')}</b> — {t('connect this device to your contacts')}</Text>
            </Stack>

            <Group justify="flex-end">
              <Button rightSection={<IconArrowRight size={16} />} loading={busy} onClick={start}>
                {t('Start using the proxy')}
              </Button>
            </Group>

            <Text size="xs" c="dimmed">
              {t('Example:')} <Code>curl -x {state.address} https://example.com</Code>
            </Text>
          </Stack>
        </Card>
      </Container>
    </Center>
  )
}
