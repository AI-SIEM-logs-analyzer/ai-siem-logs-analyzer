# Architecture

> **Skeleton.** This document describes the target architecture and marks what is already
> in place. Sections tagged **TBD** are decisions that have not been made yet; sections
> tagged **Planned** are decided but not implemented. Nothing here is binding until the
> corresponding PR lands — update this file in the same PR that changes the shape of the
> system.

## Status at a glance

| Area                                    | State       |
|-----------------------------------------|-------------|
| Local dev stack (Postgres/Redis/Redpanda) | Shipped     |
| Backend skeleton, health, OpenAPI         | Shipped     |
| PostgreSQL schema + Panache repositories  | Shipped     |
| Ingestion pipeline (Kafka)                | Shipped     |
| Detection (rules + AI)                    | In progress |
| Accounts + roles (`app_user`, `user_role`) | Shipped     |
| REST API surface                          | In progress |
| Frontend application                      | In progress |
| AuthN/AuthZ (JWT + RBAC)                  | Shipped     |
| Log search backend (OpenSearch)           | Shipped     |

## Context

The platform ingests logs from heterogeneous sources, normalises them into a common event
shape, evaluates them against detection rules and AI models, and raises alerts that an
analyst triages through a web UI.

```mermaid
%% Placeholder — replace with the real context diagram once ingestion and the API surface land.
flowchart LR
    sources[Log sources<br/>syslog · files · agents] --> ingest[Ingestion]
    ingest --> platform[SIEM Analyzer]
    platform --> ui[Analyst UI]
    platform --> notify[Notifications<br/>TBD]
```

## Component view

```mermaid
%% Placeholder — component boundaries are provisional and will move as features land.
flowchart TB
    subgraph client[Frontend]
        spa[React SPA<br/>Vite · TanStack Query · ECharts]
    end

    subgraph api[Backend — Quarkus, Java 21]
        rest[rest/<br/>HTTP boundary]
        service[service/<br/>business logic]
        repo[repo/<br/>Panache repositories]
        enrich[enrich/<br/>GeoIP · User-Agent enrichment]
        health[health/<br/>readiness · liveness]
    end

    subgraph infra[Infrastructure]
        pg[(PostgreSQL<br/>events · rules · alerts)]
        redis[(Redis<br/>cache · rate limiting)]
        kafka[[Kafka / Redpanda<br/>ingestion topics]]
        search[(OpenSearch<br/>derived event index)]
    end

    llm[LLM provider<br/>via LangChain4j]

    spa -->|REST + OpenAPI-generated client| rest
    rest --> service
    service --> repo
    repo --> pg
    service --> redis
    service --> llm
    kafka --> service
    service --> enrich
    service -.-> search
```

### Backend packages

Mirrors `com.siem.analyzer` — see [backend/README.md](../backend/README.md#package-layout).

| Package   | Responsibility                                              |
|-----------|-------------------------------------------------------------|
| `rest`    | HTTP boundary: resources, DTOs, exception mappers            |
| `service` | Business logic; the only layer that orchestrates             |
| `domain`  | JPA entities and domain enums                                |
| `repo`    | Panache repositories — every query lives here                |
| `search`  | The derived OpenSearch index — projection, queries and backfill |
| `enrich`  | GeoIP enrichment of a source address (`GeoIpEnricher` seam, MaxMind GeoLite2 lookup) and User-Agent classification (`UserAgentEnricher` seam, Yauaa) |
| `config`  | Typed `@ConfigMapping` configuration                         |
| `health`  | Custom health checks                                         |

The dependency direction is one-way: `rest → service → repo → domain`, and `rest → service →
search` alongside it. A resource never touches a repository, and a repository never returns a
DTO. The `search` package never calls back into `rest` or `service`.

## Data model

Shipped in `V1__init.sql` and `V2__users.sql`, Flyway-owned; Hibernate runs in `validate`
mode and never emits DDL.

```mermaid
erDiagram
    LOG_SOURCE ||--o{ LOG_EVENT : produces
    ALERT_RULE ||--o{ ALERT : raises
    LOG_EVENT  ||--o{ ALERT : evidences
    APP_USER   ||--|{ USER_ROLE : holds
```

| Table        | Holds                                                                    |
|--------------|--------------------------------------------------------------------------|
| `log_source` | Registered sources (name, type, configuration)                            |
| `log_event`  | Normalised events; carries the upstream identifier used to drop replays   |
| `log_event_index_state` | Which events have reached the search index; absence of a row is the backlog |
| `alert_rule` | Detection rules                                                           |
| `alert`      | Raised alerts with their triage status and the window the rule fired on; the rule is nullable — a model-raised alert has none |
| `app_user`   | Accounts; stores an Argon2id hash, never a password                       |
| `user_role`  | Roles per account (`ADMIN`, `ANALYST`, `VIEWER`); an account may hold several |

`log_event.payload` is a JSON map keyed by the component names of `NormalizedEvent` — `format`,
`host`, `srcIp`, `srcPort`, `user`, `method`, `path`, `protocol`, `status`, `bytes`, `referrer`,
`userAgent`, and whatever a parser could not place, nested under `attributes`. GeoIP enrichment
(see Cross-cutting concerns below) adds `geoCountryIso`, `geoCountryName`, `geoCity`,
`geoLocation` (a `{lat, lon}` map), `geoAsn` and `geoAsOrg` alongside them when the event's
`srcIp` resolves to a public address the databases know. User-Agent classification adds
`uaBrowser`, `uaBrowserVersion`, `uaOs`, `uaOsVersion`, `uaDeviceClass`, `uaAgentClass` and the
boolean `uaBot` when the event carries a `userAgent`. These payload keys are camelCase; the
OpenSearch document they are projected into uses snake_case for the same fields (`geo_country_iso`
… `geo_as_org`, `geo_location` as a `geo_point`, `ua_browser` … `ua_bot`) — see Search below.

## Runtime flows

**Ingestion (Producer, consumer and access-log parser shipped; file parsing planned).** An accepted upload is
stored, its metadata row is persisted, and `LogIngestProducer` publishes a JSON
`LogIngestEvent` on the `logs.ingest` channel (SmallRye Reactive Messaging, `smallrye-kafka`
connector, topic `logs.ingest`) once the enclosing transaction commits. `LogIngestConsumer`
reads the same topic on the `logs.ingest-in` channel — a second channel name on one topic,
because SmallRye would otherwise wire the outgoing channel straight into an incoming channel
of the same name and skip the broker. The consumer runs `@Blocking`, moves the upload to
`PROCESSING`, and hands the event to a `LogFileParser`. Every message is acknowledged: a
batch that cannot be handled is recorded as `FAILED` with its reason on its own row, and a
redelivered batch whose upload is already past `PENDING` is skipped rather than parsed twice.
The broker is Redpanda in the Compose stack; the test suite swaps both connectors for
`smallrye-in-memory`, so channels and payloads are exercised without a broker. Line parsers
live in `com.siem.analyzer.parse` and turn one line into a `NormalizedEvent`.
`AccessLogParser` reads Apache and Nginx Common and Combined Log Format with a java-grok
expression (`LogFormat.ACCESS_LOG`). `SyslogParser` reads RFC 5424 and BSD / RFC 3164 syslog
(`LogFormat.SYSLOG`): rsyslog files with or without a priority, the RFC 3339 high-precision
file format, and Cisco IOS / ASA lines; a year-less BSD timestamp takes the current year, or
last year when that would put it in the future. `JsonLogParser` reads one JSON object per line
with Jackson (`LogFormat.JSON`). Which key feeds which field comes from `JsonFieldMapping`,
configured under `app.parse.json.fields.*`: each field has an ordered list of dot-separated
paths that match nested objects and flat dotted keys alike, with defaults for ECS, nginx
`escape=json`, pino/bunyan, Python JSON loggers and Docker `json-file`. Unmapped keys are kept,
nested, in the event's attributes. Lines with repeated keys, trailing content or more than 64
levels of nesting are refused. Format detection supports access logs (`ACCESS_LOG`),
syslog, JSON, and fallback to plain text. `DefaultLogFileParser` reads the stored file line by line
through those parsers, normalises into `log_event` batches, enriches each event's payload with
GeoIP data for its `srcIp` and a classification of its `userAgent` (see below), indexes them via `EventIndexer.indexAfterCommit` into
OpenSearch, and calls `markIngested`. Deduplication uses the upstream identifier. Ordering
guarantees, partitioning key and retention are **TBD**.

**GeoIP enrichment (Shipped).** `com.siem.analyzer.enrich` looks up an event's `srcIp` and, when
the address is public and one of the bundled GeoLite2 databases (City, ASN) knows it, writes
`geoCountryIso`, `geoCountryName`, `geoCity`, `geoLocation`, `geoAsn` and `geoAsOrg` onto the
payload before it is persisted — the same step described just above, not a separate consumer.
`GeoIpEnricher` is the seam; `MaxMindGeoIpEnricher` is the production implementation, reading
`GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` from `app.geoip.city-database-path` /
`asn-database-path` (default `/opt/geoip/`) and refusing to boot in `%prod` if either file is
missing. Private, loopback and link-local networks are skipped before they ever reach the
database — a lookup on internal traffic has nothing useful to say. `app.geoip.enabled=false`
under `%test`, so tests substitute a `StubGeoIpEnricher` CDI mock instead of shipping real
database fixtures into every test run. Enrichment happens once, at ingestion time, rather than
on every read: a search hit's geo fields come straight out of the index with no per-request
lookup, and re-enriching each read would repeat the same MaxMind lookup for an address that
does not move between requests. The databases ship inside the container image (`src/main/jib`,
fetched from MaxMind during CI) rather than being downloaded per event or per boot, because a
GeoLite2 database is tens of megabytes, changes on MaxMind's own release cadence rather than
per deploy, and a missing network path to MaxMind at request time must never be how a log
search endpoint degrades.

**User-Agent classification (Shipped).** In the same step, `UserAgentEnricher` classifies the
event's `userAgent` and writes `uaBrowser`, `uaBrowserVersion`, `uaOs`, `uaOsVersion`,
`uaDeviceClass`, `uaAgentClass` and `uaBot` onto the payload. `YauaaUserAgentEnricher` is the
production implementation, built on [Yauaa](https://yauaa.basjes.nl/): its rule set ships inside
the library jar, so unlike GeoIP there is nothing to download, bundle or refresh — a Yauaa upgrade
is how knowledge of new browsers and crawlers arrives. The analyzer is built once at start-up
(about three seconds, restricted to the six fields read) and caches the last
`app.user-agent.cache-size` headers (default 10000), since real traffic repeats a small set of
them. `uaBot` is true for Yauaa's `Robot`, `Robot Mobile`, `Robot Imitator`, `Cloud Application`
and `Hacker` classes. Crawlers, command-line tools and HTTP libraries (curl, wget,
python-requests) and headless browsers all fall in those classes. A `Hacker` header — an injection
payload, a scanner signature such as sqlmap or Nmap, or a value no real client sends — keeps
`Hacker` in the two class fields only, so it never shows up as a browser or operating system
name. A value Yauaa does not know (`Unknown`, `??`) writes no key, and `-` (an access log's "no
header") is not classified at all. `app.user-agent.enabled=false` under `%test`, where a
`StubUserAgentEnricher` stands in so no test boot pays for the rule engine;
`YauaaUserAgentEnricherTest` runs the real one. Yauaa logs through the Log4j 2 API, which
`log4j2-jboss-logmanager` routes into the Quarkus log.

**Search (Shipped).** `log_event` is projected into an OpenSearch index addressed through the
`log-events` alias, described in [ADR 0001](adr/0001-log-search-backend.md). The index is
derived and never authoritative: PostgreSQL keeps `raw` and `payload`, and the index can be
rebuilt from them at any time. `SearchIndexInitializer` creates the index and alias at start-up
from `opensearch/log-events-mapping.json`, whose mapping is `dynamic: strict` — `message` is
`text` with a `keyword` subfield, `raw` is `wildcard` for substring matching, `src_ip` is `ip`
with `ignore_malformed`, and anything a parser could not place goes to `attributes` as a
`flat_object`, which is searchable but not efficiently aggregatable. A field the UI facets on
must therefore be mapped explicitly. `EventIndexer` writes documents under the event's own
identifier, so a redelivered batch overwrites rather than duplicating, and records the write in
`log_event_index_state`. `SearchIndexInitializer` also pushes any new mapping properties onto an
already-existing index at start-up, so a shipped mapping change (such as the geo fields) reaches
a running deployment without a manual reindex. What guarantees an event becomes searchable is
`SearchBackfillJob`, which drains the anti-join on a schedule; `indexAfterCommit` only shortens
the wait and, like `LogIngestProducer`, fires after the transaction commits. An engine that is
down degrades search and never blocks ingestion: the write is skipped, the event stays in the
backlog, and readiness is unaffected — `quarkus.elasticsearch.health.enabled` is `false` and
`SearchIndexHealthCheck` reports the engine's state as data instead. That check (`search-index`)
always answers UP and carries a `mapping` data entry of `current` or `outdated`, so a stuck
mapping push shows up as data on an otherwise-healthy check rather than as a failed readiness
probe. `GET /api/events/search` is open to every signed-in role and answers 503, not an empty
page, when the index cannot be
reached. It filters by time, source, severity, source IP (address or CIDR) and HTTP status
(code or class such as `5xx`). It sorts by event time in either direction and pages by
`search_after` cursor, never by offset. A hit does not carry the parsed fields — `srcIp`,
`userAgent`, the `geo*` and `ua*` fields, and so on — as top-level properties; they surface
generically through its `fields` map (`OpenSearchEventSearch.toHit`), converted back from the
index's snake_case to the payload's own camelCase key names (`fields.geoCountryIso`,
`fields.geoAsn`, `fields.uaBot`, …), with numbers and booleans keeping their JSON type. Its contract is documented in `/q/openapi`.

**Detection (In progress).** The rule engine is in place (`detect` package); AI-assisted
detection through LangChain4j and anomaly scoring with Smile are planned. Whether detection
runs inline with ingestion or as a separate consumer is **TBD**, so the engine is deliberately
free of persistence and CDI: it takes `NormalizedEvent`s and returns `Detection`s, and
`AlertService.raise` turns one into an `alert` row — the rule's name as the title,
`Detection.summary()` as the detail, the rule's severity, and what the window held
(`group_key`, `aggregate_value`, `event_count`, `window_start`, `window_end`).

The first built-in rule is `brute-force-login` (`BruteForceLoginRule`, seeded into
`alert_rule` by `V8__brute_force_login_rule.sql`): five or more failed logins from one `srcIp`
within a minute. A failed login is an HTTP 401/403 on a login-like path (`/login`, `/signin`,
`/auth`, `/session`, `/token`, `wp-login.php`, …) or an sshd `Failed password` /
`Failed keyboard-interactive/pam` line. For the SSH half, `SyslogParser` reads the client
address, port and user out of sshd's login messages into `srcIp`, `srcPort` and `user`, taking
the last `from <address>` so a user name cannot spoof it.

The second is `sql-injection` (`SqlInjectionRule`, seeded by `V9__sql_injection_rule.sql`),
which fires on every request whose target carries a SQL injection pattern: a quote closed into
a tautology (`' OR 1=1`, `' or 'a'='a`), `UNION SELECT`, a quote followed by a comment
(`admin'--`), `' ORDER BY n`, a stacked statement (`; DROP TABLE`), a time delay (`SLEEP(5)`,
`WAITFOR DELAY`) or a catalogue name (`information_schema`, `@@version`). It reads
`decodedPath`, a field the engine derives from `path` by percent-decoding it (up to three
times, so double encoding does not hide a quote), and accepts an inline comment wherever SQL
allows a space; `path` itself keeps what the server logged. Every gap in the pattern is
possessive, so a request the client pads to any length is still matched in linear time.

The third is `path-traversal` (`PathTraversalRule`, seeded by `V10__path_traversal_rule.sql`),
which fires on every request that climbs out of its directory or reaches for a system file: a
parent segment before a slash (`../`, `..\`, and the filter dodges `....//` and `/static../`),
one ending a segment or a query value (`/..`, `/..;/`, `?dir=..`), an IIS `%u002e`, a NUL byte,
or a file such as `/etc/passwd`, `/proc/self/environ`, `.ssh/` or `win.ini`. It reads
`decodedPath`, so `%2e%2e%2f` and `%252e%252e%252f` count as `../`, and treats the fullwidth and
division-slash look-alikes some servers fold into `.` and `/` as the real thing. Overlong UTF-8
(`%c0%af`, `%e0%80%ae`) decodes to U+FFFD, so the rule looks for it in the raw `path` instead,
encoded once or more. Browsers resolve dot segments before sending, so a `..` in the log was
sent on purpose.

The fourth is `scanner-user-agent` (`ScannerUserAgentRule`, seeded by
`V11__scanner_user_agent_rule.sql`, `WARNING`), which reads `userAgent` and fires on every
request from an attack tool that names itself (sqlmap, Nikto, the Nmap Scripting Engine,
masscan, zgrab, Nuclei, WPScan, gobuster, ffuf, Acunetix, Nessus, Hydra, ZmEu, …, as whole
words), on a header carrying a payload for whatever logs or parses it (Shellshock's `() {`,
Log4Shell's `${jndi:` and its `${${::-j}` disguises, `<script`, `UNION SELECT`, `SLEEP(5)`,
`../`), and on a command-line client or bare HTTP library (curl, Wget, python-requests,
Go-http-client, libwww-perl, PowerShell, `Java/<n>`, …) that the server answered with a 4xx
or 5xx. Those clients run health checks and scripts all day and get their 2xx, so the client
alone is not worth an alert; the same client being refused is what a hand-driven probe looks
like. A tool told to borrow a browser's header passes this rule; the rules that read what it
requests are the ones left to catch it.

A rule is the text stored in `alert_rule.expression`, parsed by `RuleExpressionParser`:

```
status in (401, 403) and path startswith "/login" | count by srcIp within 5m >= 10
status == 404 | distinct(path) by srcIp within 1m > 30
method == "GET" | sum(bytes) by srcIp within 10m > 500000000
userAgent matches "(?i)sqlmap|nikto"
```

Before the `|` is a per-event condition (`== != > >= < <=`, `in`, `exists`, `contains`,
`startswith`, `endswith`, `matches`, combined with `and`/`or`/`not`) over the standard
`NormalizedEvent` fields, the fields derived from `path` (`decodedPath`, and `uriStem` /
`uriQuery` either side of the first `?`), the `raw` line, or `attributes.<key>`. String comparisons ignore case, a number
literal compares numerically even against a quoted number, and an absent field fails every
comparison. Without a `|` the rule fires on every matching event. After it, `RuleEngine`
keeps a sliding window per group — `count`, `distinct(field)` or `sum(field)` — and fires
when the aggregate rises past the threshold, then starts that group's window over, so one
burst raises one alert rather than one per event. Windows run on event time, never the wall
clock, so replaying an uploaded file detects what a live feed would have; an event counts
while it is newer than its group's window start, and groups idle for longer than a window
are swept. Only `>`/`>=` thresholds exist: an event-driven engine cannot notice a window
closing empty.

**Sigma import.** Rules written in [Sigma](https://sigmahq.io/) are converted into this rule
language by `detect.sigma.SigmaConverter`, which reads the YAML through Jackson's YAML module
(SnakeYAML underneath), and stored by `SigmaRuleImporter` as `alert_rule` rows named
`sigma-<title>-<first 8 of id>`. Importing a rule again updates its row in place but leaves
`enabled` alone, so a rule an operator switched off stays off. What a rule means is kept, or the
rule is skipped with a reason; it is never converted into something that matches less or more:

- *Fields* map through `SigmaFieldMapping`: the Sigma `webserver` taxonomy (`c-ip`, `cs-method`,
  `cs-uri-stem`, `sc-status`, `cs-user-agent`, …) and common ECS names (`source.ip`,
  `url.path`, `user_agent.original`, …) onto the standard fields. `cs-uri-query` reads the whole
  `path`, because SigmaHQ's web rules use it for the full request target. Anything else is read
  from `attributes.<name>`; a name the rule language cannot spell is refused.
- *Log sources* become a guard ANDed in front of the rule — `method exists` for `webserver`,
  `format == "SYSLOG"` (plus the syslog tag for `sshd` and `sudo`) for Linux — so a rule built on
  a negation cannot fire on events of another kind. Log sources this platform does not ingest
  (Windows, proxies, cloud audit logs, …) are refused.
- *Values* follow Sigma: case-insensitive, `*`/`?` wildcards, lists ORed (ANDed under `|all`),
  `null` for an absent field, and keywords matched anywhere in `raw`. Supported modifiers are
  `contains`, `startswith`, `endswith`, `all`, `re` (with `i`, `m`, `s`), `cased`, `exists`,
  `lt`/`lte`/`gt`/`gte`, `base64` and `base64offset`; `cidr`, `windash`, `fieldref` and the
  UTF-16 encodings are refused.
- *Conditions* take `and`/`or`/`not`, parentheses and `1 of`/`all of` a pattern or `them`. A
  Sigma 1 aggregation (`| count() by c-ip > 10` with `timeframe`) and a Sigma 2
  `event_count`/`value_count`/`value_sum` correlation become the engine's window (`count`,
  `distinct(field)`, `sum(field)`); thresholds that fall (`<`, `lt`, …), `near` and temporal
  correlations are refused. Rules a correlation counts are not imported on their own unless it
  sets `generate: true`.
- *Metadata*: `level` maps `informational`/`low` → `INFO`, `medium` → `WARNING`, `high` →
  `ERROR`, `critical` → `CRITICAL`; the description keeps the Sigma id, author, false positives
  and references. `deprecated` and `unsupported` rules are skipped.

Nothing calls the importer yet: the rule-management API that will hand it a file is still to
come, as is where detection runs.

**Triage (In progress).** An alert is raised `NEW` and moves through `AlertStatus`
(`V12__alert_lifecycle.sql` renamed the earlier `OPEN`/`ACKNOWLEDGED`):

| From                          | To                                         |
|-------------------------------|--------------------------------------------|
| `NEW`                         | `IN_PROGRESS`, `RESOLVED`, `FALSE_POSITIVE` |
| `IN_PROGRESS`                 | `NEW`, `RESOLVED`, `FALSE_POSITIVE`         |
| `RESOLVED`, `FALSE_POSITIVE`  | `IN_PROGRESS` (reopened)                    |

`RESOLVED` and `FALSE_POSITIVE` are both closed but kept apart, because that difference is the
label a model can later learn from. `resolved_at` is set exactly while an alert is closed —
reopening clears it, and `ck_alert_resolved_at` refuses a row where the two disagree — and
`status_changed_at` records the last move. `AlertService.changeStatus` locks the row before
deciding, and refuses a move the table above does not list, including to the status the alert
already holds, with `IllegalAlertTransitionException`: of two analysts closing the same alert,
the second is told rather than silently overwriting the first. Still planned: the REST API the
SPA reads alerts through and changes their status with, and an audit of who made each move.

## Cross-cutting concerns

- **AuthN/AuthZ (Shipped).** `POST /api/auth/login` exchanges a username and password for an
  RS256 access token (15 minutes, carrying `sub`, `upn` and the account's roles as `groups`) and
  an opaque refresh token held in Redis. `@RolesAllowed` reads the roles straight off the token,
  and `quarkus.security.jaxrs.deny-unannotated-endpoints` refuses any endpoint that forgot to
  say who may call it. Refresh rotates: a token is spent once, and one presented twice revokes
  every session of that account. Logout is immediate — the access token's `jti` goes onto a
  Redis deny-list for the rest of its life — and every attempt lands in `auth_event`.
  Multi-tenancy remains **TBD**.
- **Roles per endpoint (Shipped).** Authorization is decided server-side on every endpoint;
  the SPA hides what a role cannot use, but hiding is not enforcing. Roles are declared per
  method rather than per resource class, so a method added later inherits nothing and is
  refused until someone states its rule. `/api/users` reads (`GET` on the collection and on
  one account) are open to `ADMIN`, `ANALYST` and `VIEWER`; every write — create, update,
  password reset, delete — is `ADMIN` alone. `/api/auth/login` and `/api/auth/refresh` are
  open by necessity, `/api/auth/logout` and `/api/auth/me` need any signed-in account.
  Opening the reads was a deliberate trade: any account can now enumerate usernames, e-mail
  addresses and roles, accepted because triage needs to know who owns an alert and bounded
  by what `UserResponse` carries. `UserResourceSecurityTest` and `AuthResourceSecurityTest`
  assert the whole matrix per role, `RbacJwtTest` repeats the key cases over a real token to
  prove the `groups` claim reaches the role check, and `EndpointAuthorizationCoverageTest`
  scans the compiled resources so an unannotated endpoint fails the build rather than
  answering `403` to everyone in production.
- **Credentials.** Argon2id (password4j), cost configured under `app.security.argon2`. The
  parameters are stored inside each hash, so raising them leaves existing accounts able to
  sign in. `V2__users.sql` seeds an `admin` account whose hash is the locked marker `!`,
  which matches no password — a deployment sets one through `APP_AUTH_BOOTSTRAP_PASSWORD` at
  start-up rather than inheriting a credential that would be identical everywhere.
- **Configuration.** `application.yaml` with MicroProfile Config profiles and typed
  `@ConfigMapping` interfaces. No configuration is read as loose strings.
- **Observability.** Health endpoints under `/q/health` today. Metrics and tracing are
  **TBD**.
- **API contract (Shipped).** The OpenAPI document generated at `/q/openapi` is the source of
  truth. Every backend build also writes it to `backend/target/openapi/`; a copy is committed
  as `frontend/openapi/openapi.json`, and `openapi-typescript` turns it into
  `frontend/src/api/schema.d.ts`, which types every call the SPA makes through `openapi-fetch`.
  `ci-backend` fails when the committed spec differs from the one the build produced, and
  `ci-frontend` fails when the types differ from the spec, so the contract cannot drift
  silently: `make api-client` refreshes both.
- **SPA session (Shipped).** The SPA keeps the token pair in `localStorage`, shared by every
  tab, and attaches the access token to each call. It renews the pair 30 seconds before the
  access token expires and once more on a `401`, then replays the request. Refreshes are
  serialised across tabs with a Web Lock and re-read storage inside it, because refresh
  rotation treats a second use of one token as theft. A refresh the backend refuses ends the
  session and sends the user to `/login`, which returns them where they were.
- **Errors.** Exception mapping and a common error payload shape are **TBD**.

## Decision log

Architecture decisions get one entry each, newest first. Anything marked TBD above becomes
an entry here once decided; substantial ones graduate to an ADR under `docs/adr/`.

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-10-06 | Sigma rules are imported in the JVM — Jackson YAML (SnakeYAML) into this engine's rule language — not converted offline with pySigma | One converter, in the same build and test suite as the engine, keeps the field mapping and the rule language from drifting apart, and an import needs no Python toolchain. The converter refuses what it cannot express faithfully instead of approximating it. pySigma stays the fallback, as an offline backend that emits this rule language, if rules the importer refuses turn out to matter |
| 2026-09-25 | The SPA's API client is `openapi-typescript` types over `openapi-fetch`, not a generated per-endpoint SDK (orval); the SPA stores its tokens in `localStorage` and serialises refreshes across tabs with a Web Lock | Types alone keep the generated output to one declaration file and the runtime to a few kilobytes, and TanStack Query hooks stay hand-written next to the screens that use them. `localStorage` is readable by any script on the page, but the backend issues the refresh token in the response body, not as an `HttpOnly` cookie, so no storage the SPA can reach is safer; sharing it across tabs is what keeps two tabs from spending one refresh token twice and tripping reuse detection. An `HttpOnly` refresh cookie is the upgrade path |
| 2026-09-24 | User-Agent classification uses Yauaa at ingestion time, and counts command-line tools, HTTP libraries, headless browsers and attack payloads as bots | Yauaa's rules ship inside the jar, so it adds no data file to fetch or bundle, and it classifies robots and hacking attempts, not only browsers. For a SIEM, "not a person at a browser" is the useful meaning of bot, and curl or sqlmap in a header is as automated as Googlebot |
| 2026-09-22 | GeoIP enrichment runs at ingestion time, writing geo fields onto the event payload, rather than at read time; the GeoLite2 databases are bundled into the container image rather than fetched per event | A search hit is read far more often than an event is ingested, so resolving `srcIp` once and storing the result avoids repeating the same MaxMind lookup on every page view; bundling the databases keeps a missing network path to MaxMind from ever being how the search endpoint degrades, at the cost of a larger image and a database that ages until the next deploy |
| 2026-09-15 | Log search runs on OpenSearch as a derived index; PostgreSQL stays the system of record — [ADR 0001](adr/0001-log-search-backend.md) | Aggregations and facets for the analyst dashboard are what PostgreSQL alone answers expensively; keeping the index derived means a failed index is a stale read, never lost data |

Open questions carried by this document: detection placement, ordering and retention on the
ingestion topics, tenancy model, and the error contract.
