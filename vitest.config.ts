import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    // Network tests open real sockets on loopback; keep them from hanging CI.
    testTimeout: 10_000,
  },
});
