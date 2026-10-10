import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')
  const target = env.VITE_PROXY_TARGET || 'http://localhost:8000'
  const websocketTarget = target.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:')

  return {
    plugins: [react()],
    base: './',
    server: {
      port: 3000,
      host: '0.0.0.0',
      proxy: {
        '/api/v1/ws': {
          target: websocketTarget,
          changeOrigin: true,
          ws: true,
        },
        '/api': {
          target,
          changeOrigin: true,
        },
      },
    },
  }
})
