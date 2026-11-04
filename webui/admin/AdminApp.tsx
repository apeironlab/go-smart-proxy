import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ActionIcon, AppShell, Badge, Burger, Center, Group, Loader, Menu, NavLink, ScrollArea, Text, ThemeIcon, Title, Tooltip,
  useMantineColorScheme,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import {
  IconActivity, IconApps, IconShieldOff, IconHistory, IconLanguage, IconLogout, IconMoon, IconServerCog, IconShieldLock, IconSun, IconUsers,
} from '@tabler/icons-react'
import { languages, loadLanguage } from '../src/i18n'
import { adminApi, setAuthLostHandler, setCsrf } from './api'
import type { SessionInfo } from './api'
import LoginPage from './pages/LoginPage'
import OverviewPage from './pages/OverviewPage'
import UsersPage from './pages/UsersPage'
import AccessPage from './pages/AccessPage'
import AppsPage from './pages/AppsPage'
import PolicyPage from './pages/PolicyPage'
import AuditPage from './pages/AuditPage'

export default function AdminApp() {
  const { t, i18n } = useTranslation()
  const { colorScheme, toggleColorScheme } = useMantineColorScheme()
  const [session, setSession] = useState<SessionInfo | null>(null)
  const [failed, setFailed] = useState(false)
  const [page, setPage] = useState('overview')
  const [opened, { toggle }] = useDisclosure()

  const refresh = useCallback(() => {
    adminApi.session()
      .then((s) => {
        setCsrf(s.csrf ?? '')
        setSession(s)
        setFailed(false)
      })
      .catch(() => setFailed(true))
  }, [])

  useEffect(() => {
    setAuthLostHandler(() => setSession((s) => (s ? { ...s, authenticated: false, email: undefined, csrf: undefined } : s)))
    refresh()
  }, [refresh])

  if (!session) {
    return (
      <Center h="100vh">
        {failed ? <Text c="red">{t('The relay does not answer.')}</Text> : <Loader />}
      </Center>
    )
  }
  if (!session.authenticated) {
    return <LoginPage methods={session.methods} onDone={refresh} />
  }

  const pages = [
    { id: 'overview', label: t('Overview'), icon: IconActivity, comp: <OverviewPage /> },
    { id: 'users', label: t('Users and certificates'), icon: IconUsers, comp: <UsersPage self={session.email ?? ''} /> },
    { id: 'apps', label: t('Applications'), icon: IconApps, comp: <AppsPage /> },
    { id: 'policy', label: t('Blocking'), icon: IconShieldOff, comp: <PolicyPage /> },
    { id: 'access', label: t('Access and enrollment'), icon: IconShieldLock, comp: <AccessPage /> },
    { id: 'audit', label: t('Audit log'), icon: IconHistory, comp: <AuditPage /> },
  ]

  return (
    <AppShell header={{ height: 56 }} navbar={{ width: 250, breakpoint: 'sm', collapsed: { mobile: !opened } }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" gap="sm" wrap="nowrap">
          <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
          <ThemeIcon variant="gradient" gradient={{ from: 'brand.5', to: 'cyan.5', deg: 135 }} size={34} radius="md">
            <IconServerCog size={20} />
          </ThemeIcon>
          <Title order={4} fw={700} visibleFrom="xs">{t('Relay administration')}</Title>
          <Badge variant="light" color="gray" tt="none" visibleFrom="md">{session.email}</Badge>
          <ActionIcon variant="subtle" color="gray" ml="auto" aria-label={t('Theme')} onClick={toggleColorScheme}>
            {colorScheme === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
          </ActionIcon>
          <Menu position="bottom-end" withArrow>
            <Menu.Target>
              <ActionIcon variant="subtle" color="gray" aria-label={t('Language')}>
                <IconLanguage size={18} />
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown mah={420} style={{ overflowY: 'auto' }}>
              <Menu.Label>{t('Language')}</Menu.Label>
              {languages.map((language) => (
                <Menu.Item
                  key={language.code}
                  onClick={async () => {
                    await loadLanguage(language.code)
                    await i18n.changeLanguage(language.code)
                  }}
                  fw={i18n.language === language.code ? 700 : undefined}
                >
                  {language.label}
                </Menu.Item>
              ))}
            </Menu.Dropdown>
          </Menu>
          <Tooltip label={t('Sign out')}>
            <ActionIcon
              variant="subtle" color="gray" aria-label={t('Sign out')}
              onClick={() => { void adminApi.logout().finally(refresh) }}
            >
              <IconLogout size={18} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="sm">
        <AppShell.Section grow component={ScrollArea}>
          {pages.map((p) => (
            <NavLink
              key={p.id} active={page === p.id} label={p.label} leftSection={<p.icon size={16} />}
              onClick={() => { setPage(p.id); if (opened) toggle() }}
            />
          ))}
        </AppShell.Section>
      </AppShell.Navbar>
      <AppShell.Main>{pages.find((p) => p.id === page)?.comp}</AppShell.Main>
    </AppShell>
  )
}
