import { useEffect, useState } from 'react'
import { AppShell, Alert, Anchor, Badge, Burger, Code, Group, NavLink, ScrollArea, Title, Tooltip } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconKey, IconNetwork, IconRoute, IconRouteAltRight, IconPlugConnected, IconSettings } from '@tabler/icons-react'
import ConnectionsPage from './pages/ConnectionsPage'
import CredentialsPage from './pages/CredentialsPage'
import ConfigPage from './pages/ConfigPage'
import OnboardingPage from './pages/OnboardingPage'
import RelayPage from './pages/RelayPage'
import RulesPage from './pages/RulesPage'
import { api } from './api'
import type { StateInfo } from './api'

export default function App() {
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
    const t = setInterval(load, 5000)
    const loadRelay = () =>
      api.relay().then((r) => setPending(r.approvals.length + r.incoming.length)).catch(() => {})
    loadRelay()
    const t2 = setInterval(loadRelay, 3000)
    return () => {
      clearInterval(t)
      clearInterval(t2)
    }
  }, [])

  const pages = [
    { id: 'connections', label: 'Connessioni', icon: IconPlugConnected, comp: <ConnectionsPage /> },
    { id: 'rules', label: 'Regole', icon: IconRoute, comp: <RulesPage /> },
    { id: 'relay', label: 'Relay', icon: IconRouteAltRight, comp: <RelayPage />, badge: pending },
    { id: 'credentials', label: 'Credenziali', icon: IconKey, comp: <CredentialsPage /> },
    { id: 'config', label: 'Configurazione', icon: IconSettings, comp: <ConfigPage /> },
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
        <Group h="100%" px="md" gap="sm">
          <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
          <IconNetwork size={22} />
          <Title order={4}>Go Smart Proxy</Title>
          <Code>{state?.address ?? '...'}</Code>
          <Tooltip label="Interfaccia di rete corrente">
            <Badge color="blue" variant="light">{state?.iface || '...'}</Badge>
          </Tooltip>
          <Badge color={error ? 'red' : 'green'} variant="light">
            {state ? `${state.activeConns} connessioni` : '...'}
          </Badge>
          <Tooltip label="Route forzata">
            <Badge variant="outline" color="gray">{state?.forceRoute || 'Auto'}</Badge>
          </Tooltip>
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
          <Alert color="yellow" title="Richieste in attesa" mb="md">
            Hai {pending} richieste in attesa.{' '}
            <Anchor component="button" type="button" onClick={() => setPage('relay')} fw={600}>
              Apri Relay
            </Anchor>
          </Alert>
        )}
        {pages.find((p) => p.id === page)?.comp}
      </AppShell.Main>
    </AppShell>
  )
}
