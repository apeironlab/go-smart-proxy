import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The relay administration app: built into the relay package, which embeds it
// and serves it under /admin/. During development, run the relay with the
// admin interface on and point ADMIN_BACKEND at its enrollment address.
const backend = process.env.ADMIN_BACKEND ?? 'http://localhost:8080'

export default defineConfig({
  root: 'admin',
  base: '/admin/',
  publicDir: '../public',
  plugins: [react()],
  server: {
    proxy: {
      '/admin/api': backend,
      '/enroll-auth': backend,
    },
  },
  build: {
    outDir: '../../relay/adminui/static',
    emptyOutDir: true,
  },
})
