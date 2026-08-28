import { defineConfig } from 'astro/config';

export default defineConfig({
  output: 'static',
  base: '/ui',
  build: {
    assets: 'assets',
  },
});
