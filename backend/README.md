# Backend — Quarkus (Java 21)

REST API for the SIEM log analysis platform. Currently a skeleton: health checks and
generated OpenAPI documentation, no domain features yet.

## Stack

Shipped today:

- **Quarkus 3.38.2** (Java 21) — Quarkus REST + Jackson
- **MicroProfile Config** (YAML) — `application.yaml`, profiles, typed `@ConfigMapping`
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
├── config    typed configuration mappings
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

## Configuration

All configuration lives in [`src/main/resources/application.yaml`](src/main/resources/application.yaml).
There is no `application.properties`: when both exist Quarkus silently prefers the YAML
file, so only one is kept.

### Where a value comes from

Sources, lowest precedence first:

1. `application.yaml`, including its profile blocks
2. `backend/.env` — dev mode only, git-ignored, for local secrets
3. environment variables
4. system properties (`-Dapp.environment=…`)

A key becomes an environment variable by uppercasing it and replacing dots and dashes
with underscores: `app.ai.api-key` → `APP_AI_API_KEY`, `quarkus.http.port` →
`QUARKUS_HTTP_PORT`.

### Profiles

| Profile | Activated by                       | What it changes                                     |
|---------|------------------------------------|-----------------------------------------------------|
| `dev`   | `./mvnw quarkus:dev`               | `DEBUG` logs for `com.siem`, placeholder AI key      |
| `test`  | `./mvnw test` / `verify`           | placeholder AI key, `app.environment=test`          |
| `prod`  | the packaged app (default)         | no secrets in the file — they come from the environment |

Force one explicitly with `QUARKUS_PROFILE=prod` or `-Dquarkus.profile=prod`.

### Secrets

Secrets are never committed. `app.ai.api-key` has a placeholder under `dev` and `test`
so neither the dev loop nor CI needs a real key, and no value at all under `prod`.

[`AppConfig`](src/main/java/com/siem/analyzer/config/AppConfig.java) maps the `app` tree
to a validated interface that is resolved while the application boots, so a production
start without `APP_AI_API_KEY` fails immediately and loudly:

```
Configuration validation failed:
  java.util.NoSuchElementException: SRCFG00014: The config property app.ai.api-key is
  required but it could not be found in any config source
```

To run locally with your own values:

```bash
cp backend/.env.example backend/.env   # host dev loop (./mvnw quarkus:dev)
cp docker/.env.example docker/.env     # backend in the Compose stack
```

`/q/health/ready` reports the active `app.environment`, which is the quickest way to
confirm which configuration a running instance picked up.

## Endpoints

| Endpoint          | What                                        |
|-------------------|---------------------------------------------|
| `/q/health`       | aggregate health                            |
| `/q/health/live`  | liveness                                    |
| `/q/health/ready` | readiness, including the `app-readiness` check |
| `/q/openapi`      | OpenAPI document                            |
| `/q/swagger-ui`   | Swagger UI (enabled outside dev mode too)   |

## Container image

Built with Jib, from `quarkus.container-image.*` in `application.yaml` — there is
no `Dockerfile`. `.github/workflows/cd.yml` publishes the same build to ghcr.io on merge
to `main`.

```bash
./mvnw package -DskipTests -Dquarkus.container-image.build=true
```

## CI

[`.github/workflows/ci-backend.yml`](../.github/workflows/ci-backend.yml) — Temurin 21,
`spotless:check`, then `clean verify`, and it uploads the JaCoCo report.
