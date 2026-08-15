# ai-siem-logs-analyzer

AI-assisted SIEM log analysis platform.

## Monorepo layout

| Path        | What                                              |
|-------------|---------------------------------------------------|
| `backend/`  | Quarkus (Java 21) REST API — see [backend/README.md](backend/README.md) |
| `frontend/` | React + Vite + TypeScript UI — see [frontend/README.md](frontend/README.md) |
| `docker/`   | Compose / infra (placeholder)                     |
| `docs/`     | Architecture & docs (placeholder)                 |

## Stack

**Backend:** Quarkus (Java 21) · Quarkus REST + Jackson · Hibernate ORM Panache · Flyway · Hibernate Validator · SmallRye JWT (RBAC `@RolesAllowed`) · SmallRye Reactive Messaging + Kafka (Redpanda) · Quarkus Redis · LangChain4j · Smile · Maven · JUnit 5 + RestAssured + Testcontainers + JaCoCo

**Frontend:** React + Vite + TypeScript · TanStack Query · shadcn/ui + Tailwind · Apache ECharts · OpenAPI-generated type-safe client · Vitest + Playwright

**Storage:** PostgreSQL · Redis · Kafka (Redpanda) · OpenSearch (decision pending)

## Workflow

- `main` is protected — no direct pushes.
- All changes via Pull Request, **min. 1 review** required.
- CI runs per-area (`ci-backend`, `ci-frontend`) + CodeQL security scan.

> Backend/frontend are placeholder scaffolding for now; buildable projects land in later PRs.
