# Docker — local development stack

PostgreSQL · Redis · Redpanda (Kafka-compatible, single node).

OpenSearch is still a pending decision and is not part of this stack yet.

## Quick start

```bash
make up            # creates docker/.env on first run, then starts everything
```

Equivalent without Make:

```bash
cp docker/.env.example docker/.env
docker compose -f docker/docker-compose.yml up -d --wait
```

`--wait` blocks until every healthcheck reports healthy, so the command only
returns once the stack is actually usable.

## Services

| Service    | Host address                            | Notes                                       |
|------------|-----------------------------------------|---------------------------------------------|
| PostgreSQL | `localhost:5432`                        | db/user/password from `docker/.env`         |
| Redis      | `localhost:6379`                        | password-protected, AOF persistence on      |
| Redpanda   | `localhost:19092` (Kafka API)           | from other containers: `redpanda:9092`      |
|            | `localhost:18081` (Schema Registry)     |                                             |
|            | `localhost:18082` (HTTP Proxy)          |                                             |
|            | `localhost:19644` (Admin API)           |                                             |
| Console    | `http://localhost:8085`                 | optional, `--profile tools` only            |
| Backend    | `http://localhost:8080`                 | optional, `--profile app` only              |

Redpanda advertises two listeners: `internal` for containers on the compose
network and `external` for processes on the host (backend started from Maven or
the IDE, `rpk`, test runners).

## Commands

| Command        | What it does                                            |
|----------------|---------------------------------------------------------|
| `make up`      | Start the stack, wait for healthchecks                  |
| `make tools`   | Same, plus Redpanda Console on `:8085`                  |
| `make up-app`  | Same, plus the backend API on `:8080` (builds it first) |
| `make image`   | Build the backend image with Jib, nothing else          |
| `make verify`  | Run the backend build the way CI does (Temurin 21)      |
| `make ps`      | Service status                                          |
| `make logs`    | Tail all logs                                           |
| `make stop`    | Stop containers, keep them                              |
| `make down`    | Remove containers, **keep** volumes                     |
| `make reset`   | Remove containers **and volumes** — all local data lost |

## Running the backend in the stack

`make up` starts infrastructure only. The everyday backend loop is
`./mvnw quarkus:dev` on the host, with live reload — an image rebuild per edit is
much slower.

`make up-app` is for demos, frontend work and end-to-end smoke tests. It builds the
image with Jib and starts it under the `app` profile:

```bash
make up-app
curl http://localhost:8080/q/health/ready
```

The container is only reported healthy once `/q/health/ready` answers, so
`--wait` returns when the API is genuinely serving.

There is no `Dockerfile` for the backend, by design. The image is defined once, by
the Jib configuration in `backend/src/main/resources/application.yaml`, and
`.github/workflows/cd.yml` publishes that same build to ghcr.io.

`docker/builder.Dockerfile` is a tooling image, not part of the stack: Temurin 21
(matching CI) plus Maven and the `docker` CLI, so Jib can hand the finished image to
the host's Docker daemon.

On Apple Silicon the image runs emulated — Jib targets `linux/amd64`, which is what
production runs. Startup is a little slower; nothing else changes.

## Configuration

All settings live in `docker/.env` (git-ignored), created from
`docker/.env.example`. Ports, credentials and image versions are overridable
there; the compose file falls back to sane defaults for everything except the
credentials, which are required.

The backend container runs the `prod` Quarkus profile, which carries no secrets of its
own: `APP_AI_API_KEY` is passed in from `docker/.env`, and Compose refuses to start the
service without it. Host-side development is separate — `./mvnw quarkus:dev` reads
`backend/.env` instead. See [backend/README.md](../backend/README.md#configuration).

## Persistence

Named volumes survive `make down` and container restarts:

- `pgdata` — PostgreSQL data directory
- `redisdata` — Redis AOF
- `redpandadata` — Redpanda log segments

Use `make reset` to wipe them.

## Backend connection settings

```properties
quarkus.datasource.jdbc.url=jdbc:postgresql://localhost:5432/siem
quarkus.datasource.username=siem
quarkus.datasource.password=siem_local_dev

quarkus.redis.hosts=redis://localhost:6379
quarkus.redis.password=redis_local_dev

kafka.bootstrap.servers=localhost:19092
```

## Notes

- Schema management is Flyway's job in the backend — no SQL init scripts here.
- Redpanda runs in `dev-container` mode: single node, no replication, tuned for
  a laptop. Not a production configuration.
- Integration tests use Testcontainers and spin up their own containers; they do
  not depend on this stack.
