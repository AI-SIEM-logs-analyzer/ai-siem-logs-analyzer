COMPOSE := docker compose -f docker/docker-compose.yml

.PHONY: up down stop logs ps reset tools help

## Start the dev stack (creates docker/.env from the example on first run)
up: docker/.env
	$(COMPOSE) up -d --wait

## Start the dev stack plus optional tooling (Redpanda Console)
tools: docker/.env
	$(COMPOSE) --profile tools up -d --wait

## Stop and remove containers (volumes are kept)
down:
	$(COMPOSE) --profile tools down

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
	$(COMPOSE) --profile tools down -v

docker/.env:
	cp docker/.env.example docker/.env
	@echo "Created docker/.env from docker/.env.example"

help:
	@grep -B1 -E '^[a-z-]+:' $(MAKEFILE_LIST) | grep -E '^##|^[a-z-]+:' | sed 's/^## /  /'
