import React from 'react'
import ReactDOM from 'react-dom/client'
import { MantineProvider } from '@mantine/core'
import '@mantine/core/styles.css'
import '../src/styles.css'
import '../src/i18n'
import AdminApp from './AdminApp'
import { theme } from '../src/theme'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <AdminApp />
    </MantineProvider>
  </React.StrictMode>,
)
