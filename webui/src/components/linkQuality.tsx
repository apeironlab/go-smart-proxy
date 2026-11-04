import { ActionIcon, Badge, Group, Loader, Tooltip } from '@mantine/core'
import { IconRefresh } from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'

/** The latest probe of one path through the relay. */
export type Probe =
  | { state: 'pending' }
  | { state: 'done'; ok: boolean; rttMs?: number; error?: string; at: number }

export type Quality = 'good' | 'ok' | 'slow'

/** Round-trip thresholds, in milliseconds. */
export const qualityOf = (rttMs: number): Quality => (rttMs < 150 ? 'good' : rttMs < 400 ? 'ok' : 'slow')

const colors: Record<Quality, string> = { good: 'green', ok: 'yellow', slow: 'orange' }

/** The fastest successful probe among several, if any. */
export function bestProbe(probes: (Probe | undefined)[]): { rttMs: number } | null {
  let best: number | null = null
  for (const p of probes) {
    if (p && p.state === 'done' && p.ok && p.rttMs !== undefined && (best === null || p.rttMs < best)) best = p.rttMs
  }
  return best === null ? null : { rttMs: best }
}

/** Badge showing the result of a probe, with an optional re-test button. */
export function ProbeBadge({ probe, onTest }: { probe?: Probe; onTest?: () => void }) {
  const { t } = useTranslation()
  let badge
  if (!probe) {
    badge = <Badge size="sm" variant="outline" color="gray" tt="none">{t('not tested')}</Badge>
  } else if (probe.state === 'pending') {
    badge = <Loader size={14} />
  } else if (probe.ok && probe.rttMs !== undefined) {
    const q = qualityOf(probe.rttMs)
    badge = (
      <Tooltip label={t('Round trip through the relay to this computer. A real connection also pays the latency of the contact\'s own network.')} multiline w={280}>
        <Badge size="sm" variant="light" color={colors[q]} tt="none">{Math.round(probe.rttMs)} ms · {t(q === 'good' ? 'fast' : q === 'ok' ? 'usable' : 'slow')}</Badge>
      </Tooltip>
    )
  } else {
    badge = (
      <Tooltip label={probe.error || t('no answer')} multiline w={280}>
        <Badge size="sm" variant="light" color="red" tt="none">{t('unreachable')}</Badge>
      </Tooltip>
    )
  }
  return (
    <Group gap={4} wrap="nowrap">
      {badge}
      {onTest && (!probe || probe.state !== 'pending') && (
        <ActionIcon size="sm" variant="subtle" color="gray" onClick={onTest} title={t('Test')} aria-label={t('Test')}>
          <IconRefresh size={14} />
        </ActionIcon>
      )}
    </Group>
  )
}
