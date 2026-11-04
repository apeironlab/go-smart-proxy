import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert, Button, Card, Center, Code, Group, Loader, PasswordInput, Stack, Text, ThemeIcon, Title } from '@mantine/core'
import { IconLock, IconNetwork } from '@tabler/icons-react'
import { api } from '../api'
import type { AuthInfo } from '../api'

/**
 * Shows the interface when it is open, or when the access token was given; else
 * a sign-in form. The token can arrive in the address after a "#" (the tray and
 * the "open" actions put it there): it is used and removed from the address bar.
 */
export function LoginGate({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [info, setInfo] = useState<AuthInfo | null>(null)
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = () => api.authInfo().then(setInfo).catch(() => setInfo({ required: false, imposed: false, signedIn: true }))

  useEffect(() => {
    const fromHash = new URLSearchParams(window.location.hash.replace(/^#/, '')).get('token')
    const start = async () => {
      if (fromHash) {
        history.replaceState(null, '', window.location.pathname + window.location.search)
        try {
          await api.login(fromHash)
        } catch {
          /* the form below tells */
        }
      }
      await refresh()
    }
    void start()
    // a call answered 401 (the session ended, the token changed)
    const onAuth = () => { void refresh() }
    window.addEventListener('gsp-auth-required', onAuth)
    return () => window.removeEventListener('gsp-auth-required', onAuth)
  }, [])

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.login(token.trim())
      setToken('')
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  if (!info) return <Center h="100vh"><Loader /></Center>
  if (!info.required || info.signedIn) return <>{children}</>

  return (
    <Center mih="100vh" p="md">
      <Card withBorder padding="xl" w={460} maw="100%">
        <Stack gap="md">
          <Group gap="sm" wrap="nowrap">
            <ThemeIcon variant="gradient" gradient={{ from: 'brand.5', to: 'cyan.5', deg: 135 }} size={44} radius="md"><IconNetwork size={24} /></ThemeIcon>
            <div>
              <Title order={3}>Go Smart Proxy</Title>
              <Text size="sm" c="dimmed">{t('This interface needs the access token.')}</Text>
            </div>
          </Group>
          {info.imposed && <Alert color="blue" variant="light">{t('Your organization requires the access token.')}</Alert>}
          {error && <Alert color="red" variant="light">{error}</Alert>}
          <form onSubmit={(e) => { e.preventDefault(); void submit() }}>
            <Stack gap="sm">
              <PasswordInput label={t('Access token')} value={token} onChange={(e) => setToken(e.currentTarget.value)} autoComplete="off" required autoFocus />
              <Button type="submit" loading={busy} leftSection={<IconLock size={16} />} disabled={!token.trim()}>{t('Sign in')}</Button>
            </Stack>
          </form>
          <Text size="xs" c="dimmed">
            {t('Open the interface from the tray icon (it signs you in), or copy the token from the file')} {info.tokenFile && <Code>{info.tokenFile}</Code>}
          </Text>
        </Stack>
      </Card>
    </Center>
  )
}
