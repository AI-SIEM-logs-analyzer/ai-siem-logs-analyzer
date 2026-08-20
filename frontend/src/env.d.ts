// Build-time environment the app reads. Vite substitutes `import.meta.env.*` at build
// time; declaring the shape here keeps it typed before the Vite scaffold lands (which
// brings `vite/client` and its own reference in this file).
interface ImportMetaEnv {
  /** Base URL of the Quarkus backend, e.g. `http://localhost:8080`. */
  readonly VITE_API_BASE_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
