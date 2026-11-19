import { defineConfig } from "vitest/config";

// "nstorage-source" export condition → tests run against src/*.ts, not dist/.
export default defineConfig({
  resolve: { conditions: ["nstorage-source"] },
  ssr: { resolve: { conditions: ["nstorage-source"] } },
  test: { include: ["*/test/**/*.test.ts"], testTimeout: 20000 },
});
