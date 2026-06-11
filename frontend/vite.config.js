import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': 'http://backend:8000',
      '/stream': 'http://backend:8000',
    }
  },
  build: {
    rollupOptions: {
      input: {
        main: './index.html',
        login: './login.html'
      }
    }
  }
})
