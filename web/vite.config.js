import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// CHANGE this to your actual repo name
const repoName = 'Identifying-Cryptographic-Function-in-Blockchain';

export default defineConfig({
  plugins: [react()],
  base: `/${repoName}/`,
})
