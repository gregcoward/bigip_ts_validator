import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        // Remediation (RPM install, AS3, TS) can run for many minutes; avoid proxy cutting the connection early.
        timeout: 900_000,
        proxyTimeout: 900_000,
      },
    },
  },
});
