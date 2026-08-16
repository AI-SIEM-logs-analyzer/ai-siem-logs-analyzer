# ai-siem-logs-analyzer

AI-assisted SIEM log analysis platform.

## Monorepo layout

| Path        | What                                              |
|-------------|---------------------------------------------------|
| `backend/`  | Quarkus (Java 21) REST API — see [backend/README.md](backend/README.md) |
| `frontend/` | React + Vite + TypeScript UI — see [frontend/README.md](frontend/README.md) |
| `docker/`   | Local dev stack (Compose) — see [docker/README.md](docker/README.md) |
| `docs/`     | Architecture & docs (placeholder)                 |

## Stack

**Backend:** Quarkus (Java 21) · Quarkus REST + Jackson · Hibernate ORM Panache · Flyway · Hibernate Validator · SmallRye JWT (RBAC `@RolesAllowed`) · SmallRye Reactive Messaging + Kafka (Redpanda) · Quarkus Redis · LangChain4j · Smile · Maven · JUnit 5 + RestAssured + Testcontainers + JaCoCo

**Frontend:** React + Vite + TypeScript · TanStack Query · shadcn/ui + Tailwind · Apache ECharts · OpenAPI-generated type-safe client · Vitest + Playwright

**Storage:** PostgreSQL · Redis · Kafka (Redpanda) · OpenSearch (decision pending)

## Local development

```bash
make up      # PostgreSQL + Redis + Redpanda, healthchecked, persistent volumes
make up-app  # the same, plus the backend API on :8080
make verify  # run the backend build exactly as CI does (Temurin 21, in a container)
```

Details, ports and connection settings: [docker/README.md](docker/README.md).

## Workflow

- `main` is protected — no direct pushes.
- All changes via Pull Request, **min. 1 review** required.
- CI runs per-area (`ci-backend`, `ci-frontend`) + CodeQL security scan.

> The backend is a buildable Quarkus skeleton (health + OpenAPI); domain features land in
> later PRs. The frontend is still placeholder scaffolding.
