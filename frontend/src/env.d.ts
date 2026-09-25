// Build-time environment the app reads. Vite substitutes `import.meta.env.*` at build
// time; `vite/client` (listed in tsconfig.json `types`) supplies the rest of the shape.
interface ImportMetaEnv {
  /**
   * Base URL of the Quarkus backend, e.g. `https://siem.example.com`. Leave it unset in
   * development: requests then stay same-origin and the Vite dev server proxies `/api` and
   * `/q` to the backend on localhost:8080 (see vite.config.ts).
   */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
