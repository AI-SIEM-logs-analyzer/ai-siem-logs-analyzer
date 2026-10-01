# Frontend — React + Vite + TypeScript

The analyst UI. Scaffolded: routing, layout, data fetching, sign-in and the component kit
are in place; the dashboard charts events over time and shows live backend health, and the
other pages are placeholders until their features land.

## Stack

- **React 19** + **Vite** + **TypeScript** (strict)
- **React Router** — data router, route table in [`src/app/routes.tsx`](src/app/routes.tsx)
- **TanStack Query** — server state; client defaults in
  [`src/app/query-client.ts`](src/app/query-client.ts)
- **shadcn/ui** + **Tailwind CSS v4** — theme tokens in [`src/index.css`](src/index.css)
- **Apache ECharts** — tree-shaken, SVG renderer, loaded with the first chart; wrapper in
  [`src/components/charts/echart.tsx`](src/components/charts/echart.tsx)
- Type-safe API client generated from the Quarkus **OpenAPI** spec — **openapi-typescript**
  types over **openapi-fetch**
- **Vitest** + Testing Library (unit) · **Playwright** (e2e, planned)
- **pnpm** package manager

## Run

```bash
pnpm install
pnpm dev          # http://localhost:5173
pnpm build        # typecheck, then production build into dist/
pnpm preview      # serve dist/
pnpm test         # Vitest, once
pnpm test:watch   # Vitest, watching
pnpm api:generate # regenerate src/api/schema.d.ts from openapi/openapi.json
pnpm api:check    # fail if src/api/schema.d.ts is out of date — what CI runs
```

`pnpm dev` proxies `/api` and `/q` to the backend on `http://localhost:8080` (start it as in
the [root README](../README.md#quick-start)), so the browser only ever talks to one origin
and the backend needs no CORS. Set `VITE_API_BASE_URL` (see [`.env.example`](.env.example))
only for a build served from a different origin than the API.

## Layout

```
openapi/openapi.json    the backend's OpenAPI spec, committed — generated, never edited
src/
  main.tsx              entry: query client + browser router
  app/                  providers, query client defaults, route table
  api/                  one module per backend resource: types + TanStack Query hooks
    schema.d.ts         types generated from openapi/openapi.json — never edited
    client.ts           `api`, the authenticated typed client
  components/
    layout/             app shell (sidebar, navigation)
    auth/               RequireAuth, RequirePermission (route guards) and Can
    ui/                 shadcn/ui components — vendored, edit freely
  lib/                  api-client (typed client factory, unwrap, ApiError), cn()
    auth/               session store, token refresh, useSession()
  pages/                one component per route
  test/                 Vitest setup and render helpers
```

- Imports use the `@/` alias for `src/` (tsconfig `paths` + Vite `resolve.alias`).
- A new page: add a component under `pages/`, a route in `app/routes.tsx` and, if it belongs
  in the sidebar, an entry in `components/layout/nav-items.ts`.
- A page or action for some roles only: add a permission to `lib/auth/permissions.ts`
  mirroring the backend's `@RolesAllowed`, wrap the route in `<RequirePermission>`, give its
  nav item the same `permission`, and wrap actions in `<Can>`. This only hides what the
  backend would refuse anyway; the backend stays the control.
- A new endpoint: add its query keys and hook under `api/`, calling
  `unwrap(api.GET('/api/…'))`. Paths, parameters, bodies and responses are typed from the
  spec, so take types from `components['schemas']` rather than writing them. Non-2xx responses
  throw `ApiError`; queries do not retry on 4xx.

## API client

The backend's OpenAPI document is committed as [`openapi/openapi.json`](openapi/openapi.json)
and turned into [`src/api/schema.d.ts`](src/api/schema.d.ts) by `openapi-typescript`. After
changing an endpoint in the backend, run from the repository root:

```bash
make api-client   # build the backend, copy its spec here, regenerate the types
```

then fix whatever `pnpm typecheck` now reports. CI checks both halves: `ci-backend` that the
committed spec is what the backend serves, `ci-frontend` that the types are what the spec
generates.

The spec marks response properties optional (the backend does not declare them required), so
the types do too: read them with `?.` and `??`.

## Sign-in and the session

- `/login` exchanges credentials for a token pair (`POST /api/auth/login`). Every other route
  sits behind `RequireAuth`, which sends a signed-out visitor to `/login?redirect=…` and back
  once they are in. Only same-origin paths are followed.
- The pair lives in `localStorage` ([`lib/auth/session.ts`](src/lib/auth/session.ts)), shared by
  every tab; a sign-in or sign-out in one tab applies to all.
- `api` ([`lib/auth/auth-fetch.ts`](src/lib/auth/auth-fetch.ts)) sends the access token as a
  bearer, renews the pair 30 seconds before it expires, and on a `401` renews once and replays
  the request. Concurrent requests share one refresh, and a Web Lock does the same across
  tabs: the backend rotates refresh tokens and treats a second use of one as theft.
- A refresh the backend refuses ends the session and lands on `/login?expired=1`, which says
  so. A backend that cannot be reached keeps the session: the next request tries again.
- Sign-out revokes the tokens on the backend (`POST /api/auth/logout`) and always ends the
  local session; the query cache is cleared whenever a session ends.

## Log uploads

- `/uploads` offers admins and analysts a file picker with drag and drop. The extension, an
  empty file and the 50 MiB limit are checked before anything is sent (mirroring
  `app.upload` in the backend's `application.yaml`; the backend still has the final say).
- [`api/uploads.ts`](src/api/uploads.ts) sends the file with `XMLHttpRequest` rather than
  `fetch`, which cannot report upload progress. It keeps `authFetch`'s contract by hand: the
  bearer of a fresh session, one renewal and resend on a `401`. A refusal (`413`, `415`,
  `429`, …) becomes an `ApiError` and a plain-language message; an upload can be cancelled.
- Once accepted, `GET /api/logs/uploads/{id}` is polled every 2 seconds until the status is
  `INGESTED` (with the event count) or `FAILED` (with the backend's error message). The list
  below polls the same way while any row on it is still `PENDING` or `PROCESSING`.

## Dashboard: event timeline

- The dashboard opens on events over time across every source, as columns. The range picker
  in the page header offers the last 24 hours (a column per hour), 7 days (per 3 hours) and
  30 days (per 12 hours); the choice is kept in the URL (`/?range=7d`).
- [`api/events.ts`](src/api/events.ts) asks `GET /api/events/search` for one hit with
  `facets=true` and reads the hourly counts (`facets.overTime`) and `totalHits`. The backend
  leaves out empty hours; [`lib/timeline.ts`](src/lib/timeline.ts) places the window, folds
  the hours into the coarser columns and fills the gaps with zeros. Column boundaries fall on
  local multiples of their size (12-hour columns start at midnight and noon) and always on
  whole UTC hours, so no column splits one of the backend's.
- The window ends after the current column and slides along: the timeline is fetched again
  every minute. A different range keeps the previous chart, dimmed, until its counts arrive.
- The busiest column carries its value; the tooltip gives every column's count and period, and
  “Show as table” lists them all. An empty range and an unreachable search index (`503`) are
  explained in place.
- ECharts paints with concrete colours, so
  [`event-timeline-option.ts`](src/components/dashboard/event-timeline-option.ts) mirrors the
  theme's greys and keeps a dark set for when `.dark` is on the root.
- A new chart: register its series type and components in `echart.tsx` (and in
  `EChartOption`), build the option in a plain function and render `<EChart>` lazily, as
  `event-timeline-card.tsx` does, so ECharts stays out of the main bundle.

### Adding shadcn/ui components

[`components.json`](components.json) is set up for the CLI:

```bash
pnpm dlx shadcn@latest add dialog
```

Components land in `src/components/ui/`. Run `pnpm format` afterwards — the CLI writes
double quotes.

## Format & lint

- **Prettier** — [`.prettierrc.json`](.prettierrc.json). Single quotes, trailing commas,
  100-column width, LF endings.
- **ESLint 9**, flat config — [`eslint.config.js`](eslint.config.js). `@eslint/js`
  recommended, `typescript-eslint` recommended **type-checked**, React Hooks and React
  Refresh. The chain ends with `eslint-config-prettier`, which disables every rule that
  would contradict Prettier — keep it last if you add configs.
- **TypeScript** — [`tsconfig.json`](tsconfig.json) covers `src/`,
  [`tsconfig.node.json`](tsconfig.node.json) covers `vite.config.ts`. `strict`, `noEmit`
  (Vite transpiles), bundler resolution.

```bash
pnpm lint           # ESLint
pnpm lint:fix       # ESLint, autofixing
pnpm format         # Prettier, rewriting
pnpm format:check   # Prettier, read-only — what CI runs
pnpm typecheck      # tsc --noEmit, both tsconfigs
```

`make hooks` at the repository root installs a `pre-commit` hook that runs Prettier and
ESLint over staged frontend files — see the [root README](../README.md#format--lint). pnpm
is reached through `corepack` if it is not on `PATH`.

## CI

[`.github/workflows/ci-frontend.yml`](../.github/workflows/ci-frontend.yml) — Node 22 +
pnpm, then `pnpm lint`, `pnpm format:check`, `pnpm typecheck`, `pnpm test` and the Vite
build. It runs on **every** PR, not only on the ones that touch `frontend/`, so it can be a
required status check.
