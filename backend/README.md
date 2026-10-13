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
- **password4j** — Argon2id password hashing
- **Jackson YAML** (SnakeYAML underneath) — reading Sigma rules for import
- **Smile 4.4** — Isolation Forest anomaly scoring (`detect.anomaly`); GPL-3.0, natives excluded
- **quarkus-langchain4j** (platform BOM) — LLM summaries of alerts with structured output (`ai`);
  Anthropic, OpenAI or Ollama, chosen at runtime
- **Jib** — container image, same build locally and in CD
- **Spotless** (google-java-format, AOSP) · **Checkstyle** · **JaCoCo** · **JUnit 5** + RestAssured
- **Maven** build via the wrapper (`./mvnw`)

Planned, landing in later PRs: SmallRye JWT (`@RolesAllowed`), SmallRye Reactive Messaging + Kafka, Quarkus Redis.

## Package layout

```
com.siem.analyzer
├── rest      REST resources — the HTTP boundary
├── service   business logic
├── domain    JPA entities and domain enums
├── repo      Panache repositories (all queries live here)
├── search    the derived OpenSearch index — projection, queries and backfill
├── detect    rule language and engine — per-event conditions, time-window aggregation;
│             detect.sigma converts Sigma YAML rules into that language
│             detect.anomaly scores events against a learned baseline (Isolation Forest)
├── ai        LLM assistance through quarkus-langchain4j — the alert summariser (AI service),
│             its prompt and the runtime choice of provider
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


The repository-root hook (`make hooks`) runs both on staged Java files at commit time —
see the [root README](../README.md#format--lint).

Spotless needs a JDK 21: google-java-format does not run on JDK 22+. The commit hook picks
one up automatically through `/usr/libexec/java_home -v 21` when the host has it.

## Synthetic logs for load tests

[`SyntheticLogGenerator`](src/test/java/com/siem/analyzer/loadgen/SyntheticLogGenerator.java)
writes benign traffic at any volume — 100k events by default, a million in a couple of seconds
— in the three formats the ingestion path parses:

| File              | Format                      | Content                                              |
|-------------------|-----------------------------|------------------------------------------------------|
| `access-NNNN.log` | nginx Combined Log Format   | page views, assets, API calls, crawlers, some 404/500 |
| `syslog-NNNN.log` | RFC 5424                    | SSH key logins, cron, systemd, sudo, PostgreSQL       |
| `app-NNNN.ndjson` | ECS-style JSON, unique `id` | sign-ins, orders, cart and profile events             |

It needs only a JDK, no build:

```bash
make synth-logs                                   # 100k events → backend/target/synthetic-logs
make synth-logs SYNTH_ARGS="--events 1000000 --span P7D --seed 7"
java src/test/java/com/siem/analyzer/loadgen/SyntheticLogGenerator.java --help
```

Timestamps follow a day/night curve and are written in order; users keep the same address and
browser across events. The same `--seed` and `--start` give byte-identical files, and each file
rolls over below the 50 MiB upload limit, so every file uploads as is:

```bash
for f in target/synthetic-logs/*.log target/synthetic-logs/*.ndjson; do
  curl -s -H "Authorization: Bearer $TOKEN" -F "file=@$f" localhost:8080/api/logs/upload
done
```

### Mixing in your own scenarios

`--inject DIR` interleaves existing log files with the generated traffic — samples from a public
dataset, or scenarios you wrote for a detection rule. Each file in `DIR` is one scenario,
labelled with its file name (`ssh-sample.log` → `ssh-sample`). Its lines keep their spacing
from each other and the whole file is moved to a random point of the span; each line is sorted
into the output stream of its own format (access log, RFC 5424 / BSD syslog, JSON), with its
timestamp rewritten. Lines in none of those shapes are skipped and counted in the manifest.

```bash
make synth-logs SYNTH_ARGS="--events 500000 --inject ./scenarios"                      # each file once
make synth-logs SYNTH_ARGS="--events 500000 --inject ./scenarios --inject-ratio 0.02"  # 2% of the lines
```

`--events` stays the total: injected lines replace generated ones. With `--inject-ratio` the
files are repeated, round-robin, until they make up that share. Every injected line is listed in
`ground-truth.csv` — output file, line number, timestamp, label, instance and source line — so
detection results can be scored for hits and false positives. `manifest.json` counts the lines
per label.

`SyntheticLogsParseTest` runs the generator at 100k events and checks that every line is
accepted by the production parsers and detected as the right format; it also checks that
injected lines land where `ground-truth.csv` says and keep their relative timing.

### Detection confusion matrix

`DetectionConfusionMatrixTest` scores the built-in rules against that ground truth. It injects
the scenarios in [`src/test/resources/detection-scenarios`](src/test/resources/detection-scenarios)
into 100k generated lines, parses everything with the production parsers, feeds it to one
`RuleEngine` in timestamp order and counts TP / FP / TN / FN per rule, per log line:

| Scenario file              | Lines that should raise |
|----------------------------|-------------------------|
| `brute-force-login.log`    | `brute-force-login` — sshd (BSD, RFC 5424, `sshd-session`), web login form, JSON API |
| `sql-injection.log`        | `sql-injection` — encoded, double-encoded, comment-split and blind payloads |
| `path-traversal.log`       | `path-traversal` — `../` variants, overlong UTF-8, `%u`, NUL, sensitive files |
| `scanner-user-agent.log`   | `scanner-user-agent` — tool names, header payloads, refused CLI clients |
| `benign-lookalikes.log`    | nothing — health-check `curl`, `o'reilly` searches, 4 failed logins, failed public keys |

A scenario file is named after the rule it should raise; generated lines and any other file
should raise nothing. A windowed rule's hit covers every matching line in the window that
fired, so all five failed logins of a brute force count, not only the fifth. The test fails on
any FN or FP and names the offending lines; run it alone to read the matrices:

```bash
./mvnw test -Dtest=DetectionConfusionMatrixTest
```

```
rule                     TP     FP       TN     FN  precision  recall     FPR     F1
brute-force-login        35      0    99965      0     1.0000  1.0000 0.00000 1.0000
sql-injection            15      0    99985      0     1.0000  1.0000 0.00000 1.0000
path-traversal           13      0    99987      0     1.0000  1.0000 0.00000 1.0000
scanner-user-agent       14      0    99986      0     1.0000  1.0000 0.00000 1.0000
any rule                 77      0    99923      0     1.0000  1.0000 0.00000 1.0000
```

A new attack a rule should catch goes into its scenario file; one it should ignore goes into
`benign-lookalikes.log`.

## Persistence

- **Flyway owns the schema:** `V1__init.sql` creates the log, rule and alert tables; `V2__users.sql` adds `app_user` and `user_role`; `V8__brute_force_login_rule.sql`, `V9__sql_injection_rule.sql`, `V10__path_traversal_rule.sql` and `V11__scanner_user_agent_rule.sql` seed the built-in `brute-force-login`, `sql-injection`, `path-traversal` and `scanner-user-agent` detection rules. `V12__alert_lifecycle.sql` gives `alert` its triage statuses (`NEW`, `IN_PROGRESS`, `RESOLVED`, `FALSE_POSITIVE`) and the window a detection fired on. Hibernate ORM runs with `quarkus.hibernate-orm.schema-management.strategy=validate` so it never emits DDL.
- **Migrations:** SQL scripts live in `src/main/resources/db/migration`, named `V<n>__<description>.sql`. They are immutable once applied (Flyway validates checksums).
- **Local Dev:** `%dev` connects to the local Compose stack (`jdbc:postgresql://localhost:5432/siem`, user `siem`). Start the database with `make up` and run `./mvnw quarkus:dev`.
- **Testing:** `%test` uses Dev Services via Testcontainers to start a throwaway PostgreSQL container (`postgres:16-alpine`), requiring only a running Docker daemon.
- **Production:** `%prod` expects `QUARKUS_DATASOURCE_JDBC_URL`, `QUARKUS_DATASOURCE_USERNAME`, and `QUARKUS_DATASOURCE_PASSWORD` from the environment.
- **Entities & Repositories:** Domain classes live in `com.siem.analyzer.domain`; every query lives in an `@ApplicationScoped` repository in `com.siem.analyzer.repo` extending `PanacheRepositoryBase<T, Long>`.

## Accounts and passwords

- **Roles.** `ADMIN`, `ANALYST`, `VIEWER`, stored as rows in `user_role`. An account can hold
  several at once, so the check is always "does this set contain the role this operation
  needs" rather than a rank comparison.
- **Hashing.** Argon2id through password4j, in `PasswordService` — the only class that ever
  sees a plaintext password. Cost lives under `app.security.argon2`
  (`memory-kib`, `iterations`, `parallelism`, `hash-length-bytes`, `salt-length-bytes`) and
  defaults to the OWASP 19 MiB / t=2 / p=1 pair. Raise it until one hash takes roughly half a
  second on the target hardware; stored hashes carry their own parameters, so old accounts
  keep verifying. The `%test` profile lowers the cost so the suite can hash on every test.
- **The seeded administrator.** `V2__users.sql` inserts `admin` with the password hash `!`,
  which is not valid Argon2 and therefore matches nothing — the account exists and holds
  `ADMIN`, but cannot be signed into until a password is set:

  ```bash
  curl -X PUT http://localhost:8080/api/users/1/password \
    -H 'Content-Type: application/json' \
    -d '{"password": "<at least 12 characters>"}'
  ```

  A seeded password would be the same on every deployment that ran the migration, production
  included, which is why there is none.

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

### AI provider

Alert summaries (`POST /api/alerts/{id}/summary`) come from the LLM `app.ai.provider` names.
Every provider is built into the application, so switching is a restart, not a rebuild:

| Variable           | Default                      | What                                                |
|--------------------|------------------------------|-----------------------------------------------------|
| `APP_AI_PROVIDER`  | `anthropic`                  | `anthropic`, `openai` or `ollama`                    |
| `APP_AI_API_KEY`   | — (required under `prod`)    | the provider's key; Ollama ignores it, any value does |
| `APP_AI_MODEL`     | `claude-opus-5-5` / `gpt-5-mini` | overrides the provider's default model          |
| `APP_AI_BASE_URL`  | the provider's public API, `http://localhost:11434` for Ollama | a proxy, gateway or remote Ollama |

The answer is structured output: `ai.AlertSummarizer` is a quarkus-langchain4j AI service
whose return type, the `AlertSummary` record (`evidence`, `severity`, `attackType`, `summary`,
`recommendedAction`), becomes the JSON schema the provider must answer in — Anthropic through
`output_config.format`, OpenAI through a strict `json_schema` response format, Ollama natively —
and is parsed back into the record. The system message is a constant that holds every
instruction and no alert data; the alert, with up to 20 other events of its window, goes in the
user message as escaped JSON. `ai.Grounding` then refuses (502) an answer whose `evidence`
values, or whose IP addresses in the summary or recommended action, are not in that alert. Ollama's model (`llama3.2`) is fixed when the application
is built: change it with `-Dquarkus.langchain4j.ollama.summary-ollama.chat-model.model-id=…` on
the build. Requests time out after 120 s. Leave `APP_AI_MODEL` and `APP_AI_BASE_URL` unset
rather than empty: an empty value is refused at start-up instead of falling back to the default.

The suite never calls a provider: `ScriptedChatModel` stands in for the configured model in
every `@QuarkusTest` and answers with canned JSON, while the AI service, its prompt and the
parsing stay the real ones.

## Endpoints

| Endpoint          | What                                        |
|-------------------|---------------------------------------------|
| `/q/health`       | aggregate health                            |
| `/q/health/live`  | liveness                                    |
| `/q/health/ready` | readiness, including the `app-readiness` check |
| `/q/openapi`      | OpenAPI document                            |
| `/q/swagger-ui`   | Swagger UI (enabled outside dev mode too)   |

Every build also writes the OpenAPI document to `target/openapi/openapi.{json,yaml}`. The
frontend generates its typed client from a committed copy, `frontend/openapi/openapi.json`,
and CI fails when the two differ: after changing an endpoint or a DTO, run `make api-client`
from the repository root and commit what it changes.

Application endpoints:

| Endpoint                        | What                                          |
|---------------------------------|-----------------------------------------------|
| `GET /api/users`                | list accounts                                 |
| `POST /api/users`               | create an account with an initial password    |
| `GET /api/users/{id}`           | one account                                   |
| `PUT /api/users/{id}`           | replace e-mail, roles and enabled state       |
| `PUT /api/users/{id}/password`  | set the password                              |
| `DELETE /api/users/{id}`        | delete the account and its roles              |
| `GET /api/alerts`               | list alerts, newest first; `severity`, `status` (repeatable), `page`, `size` (≤ 100) |
| `GET /api/alerts/{id}`          | one alert, with the event that raised it      |
| `POST /api/alerts/{id}/summary` | have the configured LLM summarise the alert (`ADMIN`, `ANALYST`); 502 when the provider fails or the answer cites what the alert does not contain |

They are **unauthenticated**: nothing issues a token yet, so there is no role to check. Open,
they are a full compromise — anyone who reaches them can mint an `ADMIN` account or reset any
password — so `UserResource` carries `@UnlessBuildProfile("prod")` and is absent from a
packaged application: every path above answers 404 there, and `/q/openapi` does not list them.
They work under dev and test. The sign-in PR removes that annotation and puts
`@RolesAllowed("ADMIN")` in its place.

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

## Coverage

`clean verify` writes the report to `target/site/jacoco/`. There is no coverage
threshold: the build never fails on the number, it only publishes it.

Measuring it takes two agents rather than one. `@QuarkusTest` loads the application
classes through `QuarkusClassLoader`, after Quarkus has rewritten their bytecode — Panache
enhances every entity and repository. The standard JaCoCo agent records execution data
against bytecode that no longer matches `target/classes`, and the report drops it without
warning; measured on this project, that reported 16% line coverage while every repository
and entity showed 0% with all their tests passing. So:

- the `quarkus-jacoco` extension instruments inside the Quarkus classloader,
- `exclClassLoaders=*QuarkusClassLoader` keeps the Maven agent off those same classes,
- both write `target/jacoco.exec` (`append`, plus `quarkus.jacoco.reuse-data-file` so the
  extension does not delete the file at start-up), and `jacoco:report` turns that one file
  into one report — `quarkus.jacoco.report=false` suppresses the extension's own.

Dropping any one of those pieces silently under-reports coverage instead of failing, so
treat a sudden fall in the number as a build problem before treating it as a test problem.
