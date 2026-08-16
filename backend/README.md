# Backend — Quarkus (Java 21)

REST API for the SIEM log analysis platform. Currently a skeleton: health checks and
generated OpenAPI documentation, no domain features yet.

## Stack

Shipped today:

- **Quarkus 3.38.2** (Java 21) — Quarkus REST + Jackson
- **SmallRye Health** — `/q/health`
- **SmallRye OpenAPI** — `/q/openapi`, `/q/swagger-ui`
- **Hibernate Validator**
- **Jib** — container image, same build locally and in CD
- **Spotless** (google-java-format, AOSP) · **JaCoCo** · **JUnit 5** + RestAssured
- **Maven** build via the wrapper (`./mvnw`)

Planned, landing in later PRs: Hibernate ORM with Panache, Flyway, SmallRye JWT
(`@RolesAllowed`), SmallRye Reactive Messaging + Kafka, Quarkus Redis, LangChain4j,
Smile, Testcontainers.

## Package layout

```
com.siem.analyzer
├── rest      REST resources — the HTTP boundary
├── service   business logic
├── domain    entities and value objects
├── repo      persistence access
└── health    custom health checks
```

Packages without code yet carry a `package-info.java` describing what belongs there.

## Build and run

```bash
./mvnw quarkus:dev      # dev mode, live reload, http://localhost:8080
./mvnw clean verify     # build + tests + JaCoCo report
./mvnw spotless:apply   # fix formatting
```

Requires JDK 21. If you don't have one installed, the Make targets from the repository
root run the same commands inside a Temurin 21 container:

```bash
make verify   # exactly what CI runs: spotless:check, then clean verify
make image    # build the container image with Jib
make up-app   # dev stack + backend on :8080
```

## Endpoints

| Endpoint          | What                                        |
|-------------------|---------------------------------------------|
| `/q/health`       | aggregate health                            |
| `/q/health/live`  | liveness                                    |
| `/q/health/ready` | readiness, including the `app-readiness` check |
| `/q/openapi`      | OpenAPI document                            |
| `/q/swagger-ui`   | Swagger UI (enabled outside dev mode too)   |

## Container image

Built with Jib, from `quarkus.container-image.*` in `application.properties` — there is
no `Dockerfile`. `.github/workflows/cd.yml` publishes the same build to ghcr.io on merge
to `main`.

```bash
./mvnw package -DskipTests -Dquarkus.container-image.build=true
```

## CI

[`.github/workflows/ci-backend.yml`](../.github/workflows/ci-backend.yml) — Temurin 21,
`spotless:check`, then `clean verify`, and it uploads the JaCoCo report.
