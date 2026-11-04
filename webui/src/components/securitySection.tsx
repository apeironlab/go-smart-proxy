import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert, Badge, Button, Code, CopyButton, Group, Modal, PasswordInput, Stack, Switch, Text } from '@mantine/core'
import { IconCheck, IconCopy, IconDownload, IconKey, IconLock } from '@tabler/icons-react'
import { api } from '../api'
import type { AuthInfo, SecurityInfo } from '../api'
import { Section } from './ui'
import { usePolled } from '../usePolled'

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Change the master password; make, replace or remove the recovery key. */
export function SecuritySection() {
  const { t } = useTranslation()
  const info = usePolled<SecurityInfo>(api.security, 3000)
  const auth = usePolled<AuthInfo>(api.authInfo, 3000)
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  const [recoveryPw, setRecoveryPw] = useState('')
  const [newKey, setNewKey] = useState<string | null>(null)

  const recovered = !!info?.recovered
  const mismatch = again !== '' && again !== newPw

  const change = async () => {
    setBusy(true)
    setError(null)
    setDone(false)
    try {
      await api.changePassword(oldPw, newPw)
      setOldPw('')
      setNewPw('')
      setAgain('')
      setDone(true)
    } catch (e) {
      setError(errText(e))
    } finally {
      setBusy(false)
    }
  }

  const makeKey = async () => {
    setBusy(true)
    setError(null)
    try {
      setNewKey((await api.createRecoveryKey(recoveryPw)).key)
      setRecoveryPw('')
    } catch (e) {
      setError(errText(e))
    } finally {
      setBusy(false)
    }
  }

  const removeKey = async () => {
    if (!window.confirm(t('Remove the recovery key? A forgotten password could then not be recovered.'))) return
    setBusy(true)
    setError(null)
    try {
      await api.removeRecoveryKey(recoveryPw)
      setRecoveryPw('')
    } catch (e) {
      setError(errText(e))
    } finally {
      setBusy(false)
    }
  }

  const download = () => {
    if (!newKey) return
    const url = URL.createObjectURL(new Blob([`Go Smart Proxy recovery key\n\n${newKey}\n\nKeep it somewhere safe and apart from this computer.\n`], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'go-smart-proxy-recovery-key.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      {error && <Alert color="red" variant="light" mb="md" withCloseButton onClose={() => setError(null)}>{error}</Alert>}
      {recovered && (
        <Alert color="orange" variant="light" mb="md">
          {t('You unlocked the configuration with the recovery key. Choose a new master password now.')}
        </Alert>
      )}

      <Section
        title={t('Access token for this interface')}
        description={t('Anything that can reach 127.0.0.1 can use this interface and its API. With the token on, they need the token, kept in a file only you can read. Useful on a computer shared with others.')}
        right={auth?.required ? <Badge color="green" variant="light">{t('on')}</Badge> : <Badge color="gray" variant="light">{t('off')}</Badge>}
      >
        <Stack gap="sm" maw={460}>
          <Switch
            checked={!!auth?.required} disabled={!!auth?.imposed || !auth}
            label={auth?.imposed ? t('Required by your organization') : t('Require the access token')}
            onChange={(e) => {
              const on = e.currentTarget.checked
              setError(null)
              api.setAuthEnabled(on).then(() => api.authInfo()).catch((x: unknown) => setError(errText(x)))
            }}
          />
          {auth?.required && (
            <>
              <Text size="sm" c="dimmed">{t('The token is in')} <Code>{auth.tokenFile}</Code></Text>
              <Group>
                <Button
                  variant="default"
                  onClick={() => {
                    if (!window.confirm(t('Make a new token? Every other browser window will have to sign in again.'))) return
                    api.rotateToken().catch((x: unknown) => setError(errText(x)))
                  }}
                >{t('Make a new token')}</Button>
              </Group>
            </>
          )}
        </Stack>
      </Section>

      <Section
        title={t('Master password')}
        description={t('It encrypts the configuration, including your credentials and your relay key. Changing it re-encrypts the file at once.')}
      >
        <form onSubmit={(e) => { e.preventDefault(); void change() }}>
          <Stack gap="sm" maw={420}>
            {!recovered && (
              <PasswordInput label={t('Current password')} value={oldPw} onChange={(e) => setOldPw(e.currentTarget.value)} autoComplete="current-password" required />
            )}
            <PasswordInput label={t('New password')} description={t('At least 8 characters.')} value={newPw} onChange={(e) => setNewPw(e.currentTarget.value)} autoComplete="new-password" required />
            <PasswordInput
              label={t('Repeat the new password')} value={again} onChange={(e) => setAgain(e.currentTarget.value)} autoComplete="new-password" required
              error={mismatch ? t('The passwords do not match.') : undefined}
            />
            {done && <Alert color="green" variant="light">{t('The master password was changed.')}</Alert>}
            <Group>
              <Button type="submit" leftSection={<IconLock size={16} />} loading={busy} disabled={newPw.length < 8 || newPw !== again || (!recovered && !oldPw)}>
                {t('Change the password')}
              </Button>
            </Group>
          </Stack>
        </form>
      </Section>

      <Section
        title={t('Recovery key')}
        description={t('If you forget the master password, nothing can open the configuration, except this key. It is shown once: keep it apart from this computer, for instance in a password manager or on paper.')}
        right={info?.recoveryEnabled ? <Badge color="green" variant="light">{t('set')}</Badge> : <Badge color="gray" variant="light">{t('not set')}</Badge>}
      >
        <Stack gap="sm" maw={420}>
          {info?.recoveryEnabled && info.recoveryCreated && (
            <Text size="sm" c="dimmed">{t('Created {{date}}.', { date: new Date(info.recoveryCreated).toLocaleString() })}</Text>
          )}
          {!recovered && (
            <PasswordInput label={t('Master password')} description={t('Needed to make or remove the key.')} value={recoveryPw} onChange={(e) => setRecoveryPw(e.currentTarget.value)} autoComplete="current-password" />
          )}
          <Group>
            <Button leftSection={<IconKey size={16} />} loading={busy} disabled={!recovered && !recoveryPw} onClick={() => { void makeKey() }}>
              {info?.recoveryEnabled ? t('Make a new recovery key') : t('Make a recovery key')}
            </Button>
            {info?.recoveryEnabled && (
              <Button variant="default" color="red" disabled={!recovered && !recoveryPw} onClick={() => { void removeKey() }}>{t('Remove')}</Button>
            )}
          </Group>
          <Text size="xs" c="dimmed">{t('To use it, type it where the master password is asked when the proxy starts.')}</Text>
        </Stack>
      </Section>

      {newKey && (
        <Modal opened onClose={() => setNewKey(null)} title={t('Your recovery key')} closeOnClickOutside={false} size="lg">
          <Stack gap="sm">
            <Alert color="orange" variant="light">{t('This is the only time it is shown. Whoever has it can open your configuration: keep it private.')}</Alert>
            <Code block style={{ fontSize: 16, wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{newKey}</Code>
            <Group>
              <CopyButton value={newKey}>
                {({ copied, copy }) => (
                  <Button variant="light" onClick={copy} leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />}>{copied ? t('Copied') : t('Copy')}</Button>
                )}
              </CopyButton>
              <Button variant="light" leftSection={<IconDownload size={16} />} onClick={download}>{t('Download')}</Button>
            </Group>
            <Group justify="flex-end"><Button onClick={() => setNewKey(null)}>{t('I have saved it')}</Button></Group>
          </Stack>
        </Modal>
      )}
    </>
  )
}
