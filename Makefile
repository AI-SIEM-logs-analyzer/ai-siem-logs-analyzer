COMPOSE := docker compose -f docker/docker-compose.yml

# Temurin 21 + Maven + docker CLI. Reproduces the CI toolchain and lets Jib register the
# application image with the host's Docker daemon.
BUILDER_IMAGE := siem-builder
BUILDER_RUN := docker run --rm \
	-v "$(CURDIR)":/work \
	-v siem-m2:/root/.m2 \
	-w /work/backend \
	$(BUILDER_IMAGE)
BUILDER_RUN_DOCKER := docker run --rm \
	-v "$(CURDIR)":/work \
	-v siem-m2:/root/.m2 \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-w /work/backend \
	$(BUILDER_IMAGE)
# pnpm is frequently reachable only through Node's corepack shim rather than on PATH.
PNPM := $(shell command -v pnpm >/dev/null 2>&1 && echo pnpm || echo "corepack pnpm")

# Tests reach for a Docker daemon now: Dev Services starts PostgreSQL through
# Testcontainers. The containers it starts are siblings on the host, not children of this
# one, so the test JVM has to be told to reach them through the host rather than through its
# own localhost — that is what TESTCONTAINERS_HOST_OVERRIDE does. On Linux the host-gateway
# alias is not present by default, hence --add-host.
BUILDER_RUN_TESTS := docker run --rm \
	-v "$(CURDIR)":/work \
	-v siem-m2:/root/.m2 \
	-v /var/run/docker.sock:/var/run/docker.sock \
	--add-host host.docker.internal:host-gateway \
	-e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal \
	-w /work/backend \
	$(BUILDER_IMAGE)

.PHONY: up up-app down stop logs ps reset tools help builder image verify hooks \
	format format-backend format-frontend lint lint-backend lint-frontend

## Start the dev stack (creates docker/.env from the example on first run)
up: docker/.env
	$(COMPOSE) up -d --wait

## Start the dev stack plus optional tooling (Redpanda Console)
tools: docker/.env
	$(COMPOSE) --profile tools up -d --wait

## Start the dev stack plus the backend API (rebuilds the image first)
up-app: docker/.env image
	$(COMPOSE) --profile app up -d --wait

## Install the git hooks (format & lint on commit)
hooks:
	git config core.hooksPath .githooks
	@echo "core.hooksPath -> .githooks (bypass a single commit with --no-verify)"

## Build the backend build/tooling image
builder:
	docker build -f docker/builder.Dockerfile -t $(BUILDER_IMAGE) docker/

## Build the backend container image with Jib, into the local Docker daemon
image: builder
	$(BUILDER_RUN_DOCKER) ./mvnw -B package -DskipTests -Dquarkus.container-image.build=true

## Run the backend exactly as CI does (Temurin 21): Spotless, Checkstyle, build + tests
verify: builder
	$(BUILDER_RUN) ./mvnw -B spotless:check checkstyle:check
	$(BUILDER_RUN_TESTS) ./mvnw -B clean verify

## Format every source tree in place (Spotless + Prettier)
format: format-backend format-frontend

## Check formatting and run the linters — changes nothing, same checks as CI
lint: lint-backend lint-frontend

## Reformat the backend (Spotless, in the Temurin 21 container)
format-backend: builder
	$(BUILDER_RUN) ./mvnw -B spotless:apply

## Check the backend (Spotless + Checkstyle, in the Temurin 21 container)
lint-backend: builder
	$(BUILDER_RUN) ./mvnw -B spotless:check checkstyle:check

## Reformat the frontend (Prettier)
format-frontend: frontend/node_modules
	cd frontend && $(PNPM) format

## Check the frontend (ESLint + Prettier)
lint-frontend: frontend/node_modules
	cd frontend && $(PNPM) lint && $(PNPM) format:check

# Installed on demand, so `make lint` works on a fresh clone.
frontend/node_modules: frontend/package.json frontend/pnpm-lock.yaml
	cd frontend && $(PNPM) install
	@touch frontend/node_modules

## Stop and remove containers (volumes are kept)
down:
	$(COMPOSE) --profile tools --profile app down

## Stop containers without removing them
stop:
	$(COMPOSE) stop

## Tail logs of all services
logs:
	$(COMPOSE) logs -f

## Show service status
ps:
	$(COMPOSE) ps

## Destroy containers AND volumes — all local data is lost
reset:
	$(COMPOSE) --profile tools --profile app down -v

docker/.env:
	cp docker/.env.example docker/.env
	@echo "Created docker/.env from docker/.env.example"

help:
	@grep -B1 -E '^[a-z-]+:' $(MAKEFILE_LIST) | grep -E '^##|^[a-z-]+:' | sed 's/^## /  /'
