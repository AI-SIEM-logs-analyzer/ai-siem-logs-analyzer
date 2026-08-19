# Frontend — React + Vite + TypeScript

> Only the tooling configuration is in place. The Vite application scaffold lands in a
> later PR.

## Stack

- **React** + **Vite** + **TypeScript**
- **TanStack Query**
- **shadcn/ui** + **Tailwind CSS**
- **Apache ECharts**
- Type-safe API client generated from the Quarkus **OpenAPI** spec
- **Vitest** (unit) + **Playwright** (e2e)
- **pnpm** package manager

## Format & lint

Shipped and enforced today, before any application code exists:

- **Prettier** — [`.prettierrc.json`](.prettierrc.json). Single quotes, trailing commas,
  100-column width, LF endings.
- **ESLint 9**, flat config — [`eslint.config.js`](eslint.config.js). `@eslint/js`
  recommended plus `typescript-eslint` recommended. Type-aware rules stay off until there
  is a `tsconfig.json` to point a program at; they arrive with the scaffold.
- The chain ends with `eslint-config-prettier`, which disables every ESLint rule that would
  contradict Prettier. Keep it last if you add configs.

```bash
pnpm install        # required once, and before the commit hook can run
pnpm lint           # ESLint
pnpm lint:fix       # ESLint, autofixing
pnpm format         # Prettier, rewriting
pnpm format:check   # Prettier, read-only — what CI runs
```

`make hooks` at the repository root installs a `pre-commit` hook that runs Prettier and
ESLint over staged frontend files — see the [root README](../README.md#format--lint). pnpm
is reached through `corepack` if it is not on `PATH`.

## Build (once scaffolded)

```bash
pnpm dev        # dev server
pnpm build      # production build
pnpm test       # Vitest
```

## CI

[`.github/workflows/ci-frontend.yml`](../.github/workflows/ci-frontend.yml) — Node 22 +
pnpm, `pnpm lint` and `pnpm format:check`. The `tsc --noEmit`, Vitest and Vite build steps
return with the application scaffold.
