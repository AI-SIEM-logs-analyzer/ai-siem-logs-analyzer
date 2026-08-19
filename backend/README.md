# Backend — Quarkus (Java 21)

REST API for the SIEM log analysis platform. Currently a skeleton: health checks and
generated OpenAPI documentation, no domain features yet.

## Stack

Shipped today:

- **Quarkus 3.38.2** (Java 21) — Quarkus REST + Jackson
- **Hibernate ORM with Panache & Flyway** — PostgreSQL persistence
- **MicroProfile Config** (YAML) — `application.yaml`, profiles, typed `@ConfigMapping`
- **SmallRye Health** — `/q/health`
- **SmallRye OpenAPI** — `/q/openapi`, `/q/swagger-ui`
- **Hibernate Validator**
- **Jib** — container image, same build locally and in CD
- **Spotless** (google-java-format, AOSP) · **Checkstyle** · **JaCoCo** · **JUnit 5** + RestAssured
- **Maven** build via the wrapper (`./mvnw`)

Planned, landing in later PRs: SmallRye JWT (`@RolesAllowed`), SmallRye Reactive Messaging + Kafka, Quarkus Redis, LangChain4j, Smile.

## Package layout

```
com.siem.analyzer
├── rest      REST resources — the HTTP boundary
├── service   business logic
├── domain    JPA entities and domain enums
├── repo      Panache repositories (all queries live here)
├── config    typed configuration mappings
└── health    custom health checks
```

Packages without code yet carry a `package-info.java` describing what belongs there.

## Build and run

```bash
./mvnw quarkus:dev        # dev mode, live reload, http://localhost:8080
./mvnw clean verify       # Checkstyle + build + tests + JaCoCo report
./mvnw spotless:apply     # fix formatting
./mvnw checkstyle:check   # lint only
```

Requires JDK 21. If you don't have one installed, the Make targets from the repository
root run the same commands inside a Temurin 21 container:

```bash
make verify   # exactly what CI runs: spotless:check, checkstyle:check, clean verify
make image    # build the container image with Jib
make up-app   # dev stack + backend on :8080
```

## Format & lint

Two tools with disjoint jobs:

- **Spotless** (google-java-format, AOSP style) owns layout — indentation, wrapping, import
  order, trailing whitespace. Run `./mvnw spotless:apply` and never argue with it.
- **Checkstyle** owns what layout cannot express — naming, unused and star imports, empty
  catch blocks, `EqualsHashCode`, missing `default` in a `switch`, and similar. Rules live
  in [`config/checkstyle/checkstyle.xml`](config/checkstyle/checkstyle.xml) and contain no
  formatting checks on purpose, so the two never fight. Test sources are checked too.

`checkstyle:check` is bound to the `validate` phase, so any `./mvnw verify` fails on a
violation before a single test runs. A justified exception can be fenced off:

```java
// CHECKSTYLE:OFF
...
// CHECKSTYLE:ON
```

The repository-root hook (`make hooks`) runs both on staged Java files at commit time —
see the [root README](../README.md#format--lint).

Spotless needs a JDK 21: google-java-format does not run on JDK 22+. The commit hook picks
one up automatically through `/usr/libexec/java_home -v 21` when the host has it.

## Persistence

- **Flyway owns the schema:** `V1__init.sql` creates all initial tables, indexes and constraints. Hibernate ORM runs with `quarkus.hibernate-orm.schema-management.strategy=validate` so it never emits DDL.
- **Migrations:** SQL scripts live in `src/main/resources/db/migration`, named `V<n>__<description>.sql`. They are immutable once applied (Flyway validates checksums).
- **Local Dev:** `%dev` connects to the local Compose stack (`jdbc:postgresql://localhost:5432/siem`, user `siem`). Start the database with `make up` and run `./mvnw quarkus:dev`.
- **Testing:** `%test` uses Dev Services via Testcontainers to start a throwaway PostgreSQL container (`postgres:16-alpine`), requiring only a running Docker daemon.
- **Production:** `%prod` expects `QUARKUS_DATASOURCE_JDBC_URL`, `QUARKUS_DATASOURCE_USERNAME`, and `QUARKUS_DATASOURCE_PASSWORD` from the environment.
- **Entities & Repositories:** Domain classes live in `com.siem.analyzer.domain`; every query lives in an `@ApplicationScoped` repository in `com.siem.analyzer.repo` extending `PanacheRepositoryBase<T, Long>`.

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
`spotless:check`, `checkstyle:check`, then `clean verify`, and it uploads the JaCoCo
report.
