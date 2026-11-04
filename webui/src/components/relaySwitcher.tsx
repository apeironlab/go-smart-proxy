import { Badge, Button, Group, SegmentedControl, Text } from '@mantine/core'
import { IconPlus } from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'
import { Dot } from './ui'

export interface RelayTab {
  name: string
  connected: boolean
  /** Things waiting for you on that relay (contact requests, route approvals). */
  pending?: number
}

/** Picks which relay a page is about, and adds a new one. */
export function RelaySwitcher({
  relays, selected, onSelect, onAdd,
}: {
  relays: RelayTab[]
  selected: string
  onSelect: (name: string) => void
  onAdd?: () => void
}) {
  const { t } = useTranslation()
  return (
    <Group gap="sm" mb="lg" wrap="wrap">
      {relays.length > 0 && (
        <SegmentedControl
          value={selected}
          onChange={onSelect}
          data={relays.map((r) => ({
            value: r.name,
            label: (
              <Group gap={6} wrap="nowrap" justify="center">
                <Dot color={r.connected ? 'green' : 'red'} />
                <Text size="sm" fw={600}>{r.name}</Text>
                {!!r.pending && <Badge size="xs" color="red" circle>{r.pending}</Badge>}
              </Group>
            ),
          }))}
        />
      )}
      {onAdd && (
        <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={onAdd}>
          {t('Add relay')}
        </Button>
      )}
    </Group>
  )
}
