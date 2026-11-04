import { createTheme, rem } from '@mantine/core'
import type { MantineColorsTuple } from '@mantine/core'

// Indigo-leaning brand palette, tuned to look good in both light and dark.
const brand: MantineColorsTuple = [
  '#eef2ff', '#dfe6ff', '#bcc9ff', '#97abff', '#788fff',
  '#627dff', '#5573ff', '#4562e3', '#3b57cc', '#2f4ab5',
]

const fontStack =
  'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'

export const theme = createTheme({
  primaryColor: 'brand',
  colors: { brand },
  primaryShade: { light: 6, dark: 5 },
  fontFamily: fontStack,
  fontFamilyMonospace: 'ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace',
  headings: { fontFamily: fontStack, fontWeight: '650' },
  defaultRadius: 'md',
  cursorType: 'pointer',
  shadows: {
    xs: '0 1px 2px rgba(16, 24, 40, 0.06)',
    sm: '0 1px 3px rgba(16, 24, 40, 0.08), 0 1px 2px rgba(16, 24, 40, 0.04)',
    md: '0 6px 16px -4px rgba(16, 24, 40, 0.12), 0 2px 6px -2px rgba(16, 24, 40, 0.06)',
  },
  components: {
    Card: { defaultProps: { radius: 'lg', shadow: 'xs' } },
    Paper: { defaultProps: { radius: 'md' } },
    Button: { defaultProps: { radius: 'md', fw: 600 } },
    ActionIcon: { defaultProps: { radius: 'md' } },
    Badge: { defaultProps: { radius: 'sm', fw: 600 } },
    Modal: { defaultProps: { radius: 'lg', overlayProps: { backgroundOpacity: 0.5, blur: 4 } } },
    Menu: { defaultProps: { radius: 'md', shadow: 'md' } },
    Tooltip: { defaultProps: { radius: 'sm' } },
    Alert: { defaultProps: { radius: 'md' } },
    Code: { defaultProps: { fz: rem(12.5) } },
    TextInput: { defaultProps: { radius: 'md' } },
    PasswordInput: { defaultProps: { radius: 'md' } },
    NumberInput: { defaultProps: { radius: 'md' } },
    Select: { defaultProps: { radius: 'md' } },
    NavLink: { defaultProps: { variant: 'light' } },
    Table: {
      defaultProps: { verticalSpacing: 'sm', horizontalSpacing: 'md' },
    },
  },
})
