# Backend — Quarkus (Java 21)

> Placeholder. Project scaffolding lands in a later PR.

## Stack

- **Quarkus** (Java 21)
- **Quarkus REST** + Jackson
- **Hibernate ORM with Panache** + **Flyway** (migrations)
- **Hibernate Validator**
- **SmallRye JWT** — RBAC via `@RolesAllowed`
- **SmallRye Reactive Messaging** + Kafka (Redpanda)
- **Quarkus Redis client**
- **LangChain4j** — LLM integration
- **Smile** — machine learning
- **Maven** build (`./mvnw`)
- **JUnit 5** + RestAssured + Testcontainers + JaCoCo

## Build (once scaffolded)

```bash
./mvnw quarkus:dev      # dev mode
./mvnw clean verify     # build + tests
```

CI: [`.github/workflows/ci-backend.yml`](../.github/workflows/ci-backend.yml)
