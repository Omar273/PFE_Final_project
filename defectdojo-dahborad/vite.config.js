// The browser only ever talks to localhost:5173 and talk with  http://localhost:8080

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8080", // DefectDojo runs here — change port if needed
        changeOrigin: true,
        secure: false,
        configure: (proxy) => {
          proxy.on("error", (err) => console.log("[proxy error]", err.message));
          proxy.on("proxyReq", (_, req) => console.log("[proxy]", req.method, req.url));
        },
      },
    },
  },
});
