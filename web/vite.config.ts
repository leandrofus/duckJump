import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `bun run dev` proxies the API (and session WebSockets) to a running
// `duckjump-gw serve` on :8088 (deploy/dev.sh). `bun run build` writes into the
// gateway, which embeds the result.
export default defineConfig({
  envPrefix: ['VITE_', 'FRONTEND_URL', 'FRONTENDURL', 'DUCKJUMP_'],
  plugins: [react()],
  // logo, icon and favicon live with the other brand files
  publicDir: '../assets/brand',
  server: {
    proxy: {
      '/api': { target: 'http://127.0.0.1:8088', ws: true, changeOrigin: false },
      '/agent': { target: 'http://127.0.0.1:8088', ws: true, changeOrigin: false },
    },
  },
  build: { outDir: '../gateway/internal/server/ui/dist', emptyOutDir: true, chunkSizeWarningLimit: 1500 },
})
