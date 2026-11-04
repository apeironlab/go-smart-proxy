import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert, Button, Card, Center, Group, PasswordInput, Stack, Text, TextInput, ThemeIcon, Title } from '@mantine/core'
import { IconLock, IconServerCog } from '@tabler/icons-react'
import { adminApi } from '../api'
import type { LoginMethod } from '../api'
import { message } from '../hooks'

export default function LoginPage({ methods, onDone }: { methods: LoginMethod[]; onDone: () => void }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const forms = methods.filter((m) => m.flow === 'form')
  const [formId, setFormId] = useState(forms[0]?.id ?? '')

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      await adminApi.login(formId, user.trim(), pass)
      setPass('')
      onDone()
    } catch (e) {
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }

  const browser = async (id: string) => {
    setBusy(true)
    setError(null)
    try {
      const { authUrl } = await adminApi.loginStart(id)
      window.location.assign(authUrl)
    } catch (e) {
      setError(message(e))
      setBusy(false)
    }
  }

  return (
    <Center mih="100vh" p="md">
      <Card withBorder padding="xl" w={420} maw="100%">
        <Stack gap="md">
          <Group gap="sm" wrap="nowrap">
            <ThemeIcon variant="gradient" gradient={{ from: 'brand.5', to: 'cyan.5', deg: 135 }} size={44} radius="md">
              <IconServerCog size={24} />
            </ThemeIcon>
            <div>
              <Title order={3}>{t('Relay administration')}</Title>
              <Text size="sm" c="dimmed">{t('Sign in with an administrator account.')}</Text>
            </div>
          </Group>
          {error && <Alert color="red" variant="light">{error}</Alert>}
          {methods.length === 0 && <Alert color="yellow" variant="light">{t('No sign-in method is available for administrators.')}</Alert>}
          {forms.length > 0 && (
            <form onSubmit={(e) => { e.preventDefault(); void submit() }}>
              <Stack gap="sm">
                {forms.length > 1 && (
                  <Group gap="xs">
                    {forms.map((m) => (
                      <Button key={m.id} size="xs" variant={m.id === formId ? 'filled' : 'light'} onClick={() => setFormId(m.id)}>{m.label}</Button>
                    ))}
                  </Group>
                )}
                <TextInput label={t('User name')} value={user} onChange={(e) => setUser(e.currentTarget.value)} autoComplete="username" required autoFocus />
                <PasswordInput label={t('Password')} value={pass} onChange={(e) => setPass(e.currentTarget.value)} autoComplete="current-password" required />
                <Button type="submit" loading={busy} leftSection={<IconLock size={16} />}>{t('Sign in')}</Button>
              </Stack>
            </form>
          )}
          {methods.filter((m) => m.flow === 'browser').map((m) => (
            <Button key={m.id} variant={forms.length ? 'default' : 'filled'} loading={busy} onClick={() => { void browser(m.id) }}>
              {t('Sign in with {{name}}', { name: m.label })}
            </Button>
          ))}
        </Stack>
      </Card>
    </Center>
  )
}
