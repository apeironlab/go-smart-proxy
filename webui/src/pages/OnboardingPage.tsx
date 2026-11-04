import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert, Button, Card, Center, Code, Container, Group, SimpleGrid, Stack, Text, ThemeIcon, Title } from '@mantine/core'
import { IconArrowRight, IconCheck, IconKey, IconNetwork, IconRoute, IconRouteAltRight, IconSettings } from '@tabler/icons-react'
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

  const steps = [
    { icon: IconRoute, title: t('Rules'), text: t('destinations and dedicated routes') },
    { icon: IconKey, title: t('Credentials'), text: t('corporate proxies and authentication') },
    { icon: IconSettings, title: t('Configuration'), text: t('listeners, system proxy, PAC') },
    { icon: IconRouteAltRight, title: t('Relay'), text: t('connect this device to your contacts') },
  ]

  return (
    <Center mih="100vh" p="md">
      <Container size={680} w="100%">
        <Card withBorder shadow="md" p={{ base: 'lg', sm: 40 }} radius="xl">
          <Stack gap="lg">
            <Stack gap="xs" align="center" ta="center">
              <ThemeIcon variant="gradient" gradient={{ from: 'teal.5', to: 'cyan.5', deg: 135 }} size={64} radius="xl">
                <IconCheck size={34} />
              </ThemeIcon>
              <Title order={2}>{t('Go Smart Proxy is ready')}</Title>
              <Text size="sm" c="dimmed" maw={520}>
                {t('The configuration is encrypted with the master password chosen during setup. The default listeners are already active and the proxy is ready to use right away.')}
              </Text>
            </Stack>

            {error && <Alert color="red" withCloseButton onClose={() => setError(null)}>{error}</Alert>}

            <Card withBorder padding="md" radius="lg">
              <Stack gap="sm">
                <Group justify="space-between" wrap="nowrap">
                  <Group gap="xs"><IconNetwork size={18} /><Text fw={600}>{t('HTTP proxy and web UI')}</Text></Group>
                  <Code fz="sm" px="sm">{state.address}</Code>
                </Group>
                {state.socksAddress && (
                  <Group justify="space-between" wrap="nowrap">
                    <Group gap="xs"><IconNetwork size={18} /><Text fw={600}>{t('SOCKS5 proxy')}</Text></Group>
                    <Code fz="sm" px="sm">{state.socksAddress}</Code>
                  </Group>
                )}
                <Text size="xs" c="dimmed">
                  {t('Point your applications at one of these addresses. The listeners are loopback-only; you can change them in Configuration.')}
                </Text>
              </Stack>
            </Card>

            <div>
              <Text size="sm" fw={600} mb="xs">{t('From the web app you can now configure:')}</Text>
              <SimpleGrid cols={{ base: 1, xs: 2 }} spacing="sm">
                {steps.map((s) => (
                  <Group key={s.title} gap="sm" wrap="nowrap" align="flex-start">
                    <ThemeIcon variant="light" size={34} radius="md"><s.icon size={18} /></ThemeIcon>
                    <div>
                      <Text size="sm" fw={600}>{s.title}</Text>
                      <Text size="xs" c="dimmed">{s.text}</Text>
                    </div>
                  </Group>
                ))}
              </SimpleGrid>
            </div>

            <Button size="md" fullWidth rightSection={<IconArrowRight size={18} />} loading={busy} onClick={start}>
              {t('Start using the proxy')}
            </Button>

            <Text size="xs" c="dimmed" ta="center">
              {t('Example:')} <Code>curl -x {state.address} https://example.com</Code>
            </Text>
          </Stack>
        </Card>
      </Container>
    </Center>
  )
}
