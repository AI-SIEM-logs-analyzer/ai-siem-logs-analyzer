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

Redpanda advertises two listeners: `internal` for containers on the compose
network and `external` for processes on the host (backend started from Maven or
the IDE, `rpk`, test runners).

## Commands

| Command      | What it does                                            |
|--------------|---------------------------------------------------------|
| `make up`    | Start the stack, wait for healthchecks                  |
| `make tools` | Same, plus Redpanda Console on `:8085`                  |
| `make ps`    | Service status                                          |
| `make logs`  | Tail all logs                                           |
| `make stop`  | Stop containers, keep them                              |
| `make down`  | Remove containers, **keep** volumes                     |
| `make reset` | Remove containers **and volumes** — all local data lost |

## Configuration

All settings live in `docker/.env` (git-ignored), created from
`docker/.env.example`. Ports, credentials and image versions are overridable
there; the compose file falls back to sane defaults for everything except the
credentials, which are required.

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
