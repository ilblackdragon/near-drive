import { defineConfig } from "vitest/config";

// "near-drive-source" export condition → tests run against src/*.ts, not dist/.
export default defineConfig({
  resolve: { conditions: ["near-drive-source"] },
  ssr: { resolve: { conditions: ["near-drive-source"] } },
  test: { include: ["*/test/**/*.test.ts"], testTimeout: 20000 },
});
