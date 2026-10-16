import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
  site: process.env.SITE_URL || 'https://leandrofus.github.io',
  base: process.env.BASE_PATH !== undefined ? process.env.BASE_PATH : '/duckJump',
  trailingSlash: 'always',
  vite: {
    plugins: [tailwindcss()],
  },
});
