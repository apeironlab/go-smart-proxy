import { useTranslation } from 'react-i18next'
import { ActionIcon, Alert, Badge, Button, Card, Code, CopyButton, Group, SimpleGrid, Stack, Text, Tooltip } from '@mantine/core'
import { IconApps, IconCheck, IconCopy, IconExternalLink } from '@tabler/icons-react'
import { api } from '../api'
import type { AppEntry, StateInfo } from '../api'
import { Dot, EmptyState, PageHeader } from '../components/ui'
import { usePolled } from '../usePolled'

export default function AppsPage({ state }: { state: StateInfo | null }) {
  const { t } = useTranslation()
  const apps = usePolled<AppEntry[]>(api.apps, 3000)
  const list = apps ?? []
  const relays = new Set(list.map((a) => a.relay))

  return (
    <>
      <PageHeader
        icon={IconApps} title={t('Applications')}
        description={t('Applications your relay makes available to you. Just open them: the proxy sends the connection to the relay by itself, no route or rule is needed.')}
      />
      {list.length === 0 ? (
        <EmptyState icon={IconApps} title={t('No applications')} text={t('The relay has not published any application for you.')} />
      ) : (
        <SimpleGrid cols={{ base: 1, sm: 2, xl: 3 }}>
          {list.map((a) => (
            <Card key={a.relay + '/' + a.id} withBorder padding="lg">
              <Stack gap="xs" h="100%" justify="space-between">
                <div>
                  <Group justify="space-between" wrap="nowrap" align="flex-start">
                    <Text fw={650} size="md">{a.name}</Text>
                    <Group gap={6} wrap="nowrap">
                      <Dot color={a.online ? 'green' : 'gray'} />
                      <Text size="xs" c="dimmed">{a.online ? t('available') : t('not available')}</Text>
                    </Group>
                  </Group>
                  {a.description && <Text size="sm" c="dimmed" mt={4}>{a.description}</Text>}
                  <Group gap={6} mt="sm">
                    <Badge variant="light" tt="none">{a.kind === 'http' ? t('web') : t('network service')}</Badge>
                    {relays.size > 1 && <Badge variant="outline" color="gray" tt="none">{a.relay}</Badge>}
                  </Group>
                </div>
                <div>
                  {a.kind === 'http' ? (
                    <Button
                      component="a" href={a.url} target="_blank" rel="noopener noreferrer" mt="sm" fullWidth
                      leftSection={<IconExternalLink size={16} />} disabled={!a.online} variant={a.online ? 'filled' : 'default'}
                    >
                      {t('Open')}
                    </Button>
                  ) : (
                    <Stack gap={6} mt="sm">
                      <Group gap={6} wrap="nowrap">
                        <Code style={{ flex: 1 }}>{a.host}</Code>
                        <CopyButton value={a.host}>
                          {({ copied, copy }) => (
                            <Tooltip label={copied ? t('Copied') : t('Copy')}>
                              <ActionIcon variant="subtle" color={copied ? 'teal' : 'gray'} onClick={copy} aria-label={t('Copy')}>
                                {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                              </ActionIcon>
                            </Tooltip>
                          )}
                        </CopyButton>
                      </Group>
                      <Text size="xs" c="dimmed">
                        {t('Point your client (RDP, SSH, database tool...) at this name and set its proxy to SOCKS5 {{address}}.', { address: state?.socksAddress || '' })}
                      </Text>
                    </Stack>
                  )}
                </div>
              </Stack>
            </Card>
          ))}
        </SimpleGrid>
      )}
      {list.some((a) => a.kind === 'http') && (
        <Alert variant="light" color="gray" mt="lg">
          {t('Web applications open with http:// in your browser: the connection to the relay is already encrypted, and the gateway talks to the application on your behalf.')}
        </Alert>
      )}
    </>
  )
}
