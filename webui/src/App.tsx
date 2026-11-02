import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AppShell, Alert, Anchor, Badge, Burger, Code, Group, Menu, NavLink, ScrollArea, Title, Tooltip, ActionIcon } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconKey, IconLanguage, IconNetwork, IconRoute, IconRouteAltRight, IconPlugConnected, IconSettings } from '@tabler/icons-react'
import ConnectionsPage from './pages/ConnectionsPage'
import CredentialsPage from './pages/CredentialsPage'
import ConfigPage from './pages/ConfigPage'
import OnboardingPage from './pages/OnboardingPage'
import RelayPage from './pages/RelayPage'
import RulesPage from './pages/RulesPage'
import { api } from './api'
import { languages } from './i18n'
import type { StateInfo } from './api'

export default function App() {
  const { t, i18n } = useTranslation()
  const [page, setPage] = useState('connections')
  const [opened, { toggle }] = useDisclosure()
  const [state, setState] = useState<StateInfo | null>(null)
  const [error, setError] = useState(false)
  const [pending, setPending] = useState(0)

  useEffect(() => {
    const load = () =>
      api
        .state()
        .then((s) => {
          setState(s)
          setError(false)
        })
        .catch(() => setError(true))
    load()
    const timer = setInterval(load, 5000)
    const loadRelay = () =>
      api.relay().then((r) => setPending(r.approvals.length + r.incoming.length)).catch(() => {})
    loadRelay()
    const relayTimer = setInterval(loadRelay, 3000)
    return () => {
      clearInterval(timer)
      clearInterval(relayTimer)
    }
  }, [])

  const pages = [
    { id: 'connections', label: t('Connections'), icon: IconPlugConnected, comp: <ConnectionsPage /> },
    { id: 'rules', label: t('Rules'), icon: IconRoute, comp: <RulesPage /> },
    { id: 'relay', label: t('Relay'), icon: IconRouteAltRight, comp: <RelayPage />, badge: pending },
    { id: 'credentials', label: t('Credentials'), icon: IconKey, comp: <CredentialsPage /> },
    { id: 'config', label: t('Configuration'), icon: IconSettings, comp: <ConfigPage /> },
  ]

  if (state?.onboarding) {
    return <OnboardingPage state={state} />
  }

  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 230, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" gap="sm" wrap="nowrap">
          <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
          <IconNetwork size={22} />
          <Title order={4} visibleFrom="sm">Go Smart Proxy</Title>
          <Code visibleFrom="md">{state?.address ?? '...'}</Code>
          <Tooltip label={t('Current network interface')}>
            <Badge color="blue" variant="light" visibleFrom="md">{state?.iface || '...'}</Badge>
          </Tooltip>
          <Badge color={error ? 'red' : 'green'} variant="light" visibleFrom="sm">
            {state ? t('Active connections: {{count}}', { count: state.activeConns }) : '...'}
          </Badge>
          <Tooltip label={t('Forced route')}>
            <Badge variant="outline" color="gray" visibleFrom="sm">{state?.forceRoute || t('Auto')}</Badge>
          </Tooltip>
          <Menu position="bottom-end" withArrow>
            <Menu.Target>
              <ActionIcon variant="subtle" color="gray" aria-label={t('Language')} ml="auto">
                <IconLanguage size={18} />
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown mah={420} style={{ overflowY: 'auto' }}>
              <Menu.Label>{t('Language')}</Menu.Label>
              {languages.map((language) => (
                <Menu.Item
                  key={language.code}
                  onClick={() => i18n.changeLanguage(language.code)}
                  fw={i18n.language === language.code ? 700 : undefined}
                >
                  {language.label}
                </Menu.Item>
              ))}
            </Menu.Dropdown>
          </Menu>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="sm">
        <AppShell.Section grow component={ScrollArea}>
          {pages.map((p) => (
            <NavLink
              key={p.id}
              active={page === p.id}
              label={p.label}
              rightSection={p.badge ? <Badge color="red" size="sm" circle>{p.badge}</Badge> : null}
              leftSection={<p.icon size={16} />}
              onClick={() => setPage(p.id)}
            />
          ))}
        </AppShell.Section>
      </AppShell.Navbar>
      <AppShell.Main>
        {pending > 0 && page !== 'relay' && (
          <Alert color="yellow" title={t('Pending requests')} mb="md">
            {t('You have {{count}} pending requests.', { count: pending })}{' '}
            <Anchor component="button" type="button" onClick={() => setPage('relay')} fw={600}>
              {t('Open Relay')}
            </Anchor>
          </Alert>
        )}
        {pages.find((p) => p.id === page)?.comp}
      </AppShell.Main>
    </AppShell>
  )
}
