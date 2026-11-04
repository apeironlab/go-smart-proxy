import type { ReactNode } from 'react'
import { Box, Card, Group, Stack, Text, ThemeIcon, Title } from '@mantine/core'
import type { Icon } from '@tabler/icons-react'

/** Consistent page title with an optional description and actions on the right. */
export function PageHeader({
  title, description, actions, icon: IconCmp,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
  icon?: Icon
}) {
  return (
    <Group justify="space-between" align="flex-start" mb="lg" gap="md" wrap="wrap">
      <Group gap="sm" align="flex-start" wrap="nowrap" style={{ flex: '1 1 320px', minWidth: 0 }}>
        {IconCmp && (
          <ThemeIcon variant="light" size={40} radius="md" mt={2}>
            <IconCmp size={22} />
          </ThemeIcon>
        )}
        <Box style={{ minWidth: 0 }}>
          <Title order={3}>{title}</Title>
          {description && <Text size="sm" c="dimmed" mt={4} maw={760}>{description}</Text>}
        </Box>
      </Group>
      {actions && <Group gap="sm" wrap="wrap">{actions}</Group>}
    </Group>
  )
}

/** A titled card used to group related settings. */
export function Section({
  title, description, right, children, accent, mb = 'lg',
}: {
  title?: ReactNode
  description?: ReactNode
  right?: ReactNode
  children?: ReactNode
  accent?: string
  mb?: string
}) {
  return (
    <Card withBorder padding="lg" mb={mb} style={accent ? { borderColor: `var(--mantine-color-${accent}-6)` } : undefined}>
      {(title || right) && (
        <Group justify="space-between" align="flex-start" mb={children ? 'md' : 0} wrap="nowrap" gap="md">
          <Box style={{ minWidth: 0 }}>
            {title && <Text fw={650} size="md">{title}</Text>}
            {description && <Text size="xs" c="dimmed" mt={2} maw={680}>{description}</Text>}
          </Box>
          {right}
        </Group>
      )}
      {children}
    </Card>
  )
}

/** A compact statistic tile. */
export function StatCard({
  label, value, icon: IconCmp, color = 'brand', hint,
}: {
  label: string
  value: ReactNode
  icon?: Icon
  color?: string
  hint?: ReactNode
}) {
  return (
    <Card withBorder padding="md">
      <Group justify="space-between" wrap="nowrap" align="flex-start">
        <Box style={{ minWidth: 0 }}>
          <Text size="xs" c="dimmed" tt="uppercase" fw={650} style={{ letterSpacing: '.05em' }}>{label}</Text>
          <Text fw={700} fz={20} mt={4} style={{ lineHeight: 1.2 }} truncate="end" title={typeof value === 'string' ? value : undefined}>{value}</Text>
          {hint && <Text size="xs" c="dimmed" mt={2}>{hint}</Text>}
        </Box>
        {IconCmp && (
          <ThemeIcon variant="light" color={color} size={36} radius="md">
            <IconCmp size={19} />
          </ThemeIcon>
        )}
      </Group>
    </Card>
  )
}

/** Placeholder shown when a list is empty. */
export function EmptyState({
  icon: IconCmp, title, text, action,
}: {
  icon: Icon
  title: string
  text?: ReactNode
  action?: ReactNode
}) {
  return (
    <Stack align="center" gap="xs" py="xl" px="md" ta="center">
      <ThemeIcon variant="light" color="gray" size={52} radius="xl">
        <IconCmp size={26} />
      </ThemeIcon>
      <Text fw={600}>{title}</Text>
      {text && <Text size="sm" c="dimmed" maw={420}>{text}</Text>}
      {action}
    </Stack>
  )
}

/** A label/value pair for read-only details. */
export function Info({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div style={{ minWidth: 0 }}>
      <Text size="xs" c="dimmed">{label}</Text>
      <Text size="sm" style={{ wordBreak: 'break-word' }}>{value || '-'}</Text>
    </div>
  )
}

/** A small coloured dot, used for status. */
export function Dot({ color }: { color: string }) {
  return (
    <span
      style={{
        display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
        background: `var(--mantine-color-${color}-6)`, flex: 'none',
      }}
    />
  )
}
