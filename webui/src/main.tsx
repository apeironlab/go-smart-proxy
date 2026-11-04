import React from 'react'
import ReactDOM from 'react-dom/client'
import { MantineProvider } from '@mantine/core'
import '@mantine/core/styles.css'
import './styles.css'
import './i18n'
import App from './App'
import { LoginGate } from './components/loginGate'
import { theme } from './theme'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <LoginGate>
        <App />
      </LoginGate>
    </MantineProvider>
  </React.StrictMode>,
)
