import { Badge, Group, Tooltip } from '@mantine/core'
import { useTranslation } from 'react-i18next'
import type { NetContext } from '../api'

/**
 * What a device says about its network: a label chosen by its owner and
 * whether a VPN is active. A device that shares nothing shows a muted badge,
 * so "unknown" is never mistaken for "no VPN".
 */
export function ContextBadges({ context, online }: { context?: NetContext; online?: boolean }) {
  const { t } = useTranslation()
  if (!online) return null
  if (!context) {
    return (
      <Tooltip label={t('This device does not share its network context (older version, or sharing turned off).')} multiline w={260}>
        <Badge size="sm" variant="outline" color="gray" tt="none">{t('network unknown')}</Badge>
      </Tooltip>
    )
  }
  return (
    <Group gap={4} wrap="nowrap">
      {context.vpn
        ? <Badge size="sm" variant="light" color="grape" tt="none">VPN</Badge>
        : <Badge size="sm" variant="light" color="gray" tt="none">{t('no VPN')}</Badge>}
      {context.label && <Badge size="sm" variant="outline" color="grape" tt="none">{context.label}</Badge>}
    </Group>
  )
}
