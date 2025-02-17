import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // Listen on all network interfaces
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        secure: false
      }
    },
    allowedHosts: [
      'ajingolik.fun',
      '.ajingolik.fun' // Allows all subdomains as well
    ]
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-router-dom', 'react-dom', 'axios', '@tanstack/react-query'],
        },
      },
    },
    minify: 'terser',
    sourcemap: false,
  }
})
