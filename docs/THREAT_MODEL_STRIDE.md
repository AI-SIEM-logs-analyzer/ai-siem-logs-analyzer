# STRIDE Threat Model — AI SIEM Logs Analyzer

This document defines the formal **STRIDE Threat Model** for the **AI SIEM Logs Analyzer** platform. It analyzes system boundaries, data flows, threat vectors across the six STRIDE dimensions, and documents existing technical mitigations alongside residual risk management.

---

## 1. Scope & System Overview

The platform ingests, normalizes, detects, indexes, and triages security event logs using a reactive pipeline (Quarkus 3.x, Apache Kafka, OpenSearch, PostgreSQL, Redis) with AI-assisted alert summarization (LangChain4j + LLMs).

### Trust Boundaries (TB)
- **TB1 (Ingress / Network Edge)**: Public Internet separating external users and forwarders from the application.
- **TB2 (Web Tier / Frontend Boundary)**: Browser sandbox running the React 19 Single Page Application (SPA).
- **TB3 (Application Boundary)**: Quarkus REST API enforcing authentication, authorization, input validation, and rate limiting.
- **TB4 (Internal Core / Persistence Boundary)**: Isolated network segment for internal state stores (PostgreSQL, Redis, Apache Kafka, OpenSearch, Local Storage).
- **TB5 (Egress Boundary)**: Outbound communication channels to external AI LLM providers (e.g., OpenAI, Anthropic) or local inference engines (Ollama).

---

## 2. Data Flow Diagram (DFD)

```mermaid
flowchart TB
    subgraph TB_EXT["External Entities"]
        User["Security Personnel\n(Admin, Analyst, Viewer)"]
        LogSrc["Log Sources & Forwarders\n(Syslog / HTTP Multipart)"]
        LLM["External / Local LLM Provider\n(OpenAI / Anthropic / Ollama)"]
    end

    subgraph TB_FRONTEND["TB1 / TB2: Frontend Client Sandbox"]
        SPA["React 19 SPA\n(Tab-Locked Session / Web Locks)"]
    end

    subgraph TB_BACKEND["TB3: Quarkus Backend Service"]
        AuthRes["AuthResource\n(Login / Refresh / JWT RS256)"]
        UserRes["UserResource\n(RBAC Admin Operations)"]
        UploadRes["LogUploadResource\n(Multipart Ingest & SHA-256)"]
        SearchRes["EventSearchResource\n(Typed Query DSL)"]
        AlertRes["AlertResource\n(Triage & Detection Lifecycle)"]

        subgraph IngestionAI["Pipeline & AI Services"]
            Parsers["Log Parsers & Sanitizer\n(Syslog, JSON, Access)"]
            KafkaStream["Reactive Kafka Pipeline"]
            DetectEngine["RuleEngine + Isolation Forest"]
            AISummarizer["AI AlertSummarizer\n+ Grounding Post-Check"]
        end
    end

    subgraph TB_DATA["TB4: Internal Persistence & Broker"]
        PG[("PostgreSQL\n(Users, AuthEvents, Alerts)")]
        Redis[("Redis\n(Refresh Tokens, Rate Limit Counters)")]
        Kafka[("Apache Kafka\n(Raw & Normalized Event Topics)")]
        OS[("OpenSearch Cluster\n(Derived Event Search Index)")]
        Disk[("Staging Storage\n(Sanitized Uploads)")]
    end

    User -->|HTTPS (TLS 1.3)| SPA
    SPA -->|Bearer JWT RS256| AuthRes
    SPA -->|Bearer JWT RS256| UserRes
    SPA -->|Multipart Form Data| UploadRes
    SPA -->|Search Filters| SearchRes
    SPA -->|Triage Actions| AlertRes
    LogSrc -->|Raw Logs over HTTPS| UploadRes

    AuthRes -->|Argon2id Verification| PG
    AuthRes -->|Revocation & Refresh Token State| Redis
    AuthRes -->|Log Login/Logout Events| PG
    UserRes -->|CRUD User Entities| PG

    UploadRes -->|Write Staging File| Disk
    UploadRes -->|Enqueue Ingestion Event| KafkaStream
    KafkaStream -->|Publish Events| Kafka
    KafkaStream -->|Consume & Normalize| Parsers
    Parsers -->|Bulk Indexing| OS
    Parsers -->|Evaluate Rules & Anomalies| DetectEngine
    DetectEngine -->|Persist Alert Records| PG

    AlertRes -->|Request Summarization| AISummarizer
    AISummarizer -->|TB5 Egress Prompt| LLM
    LLM -->|Generated Summary| AISummarizer
    AISummarizer -->|Grounded Validation| PG

    SearchRes -->|Typed JSON DSL| OS
```

---

## 3. STRIDE Threat Matrix

| Threat Category | ID | Target Component | Threat Scenario | Impact | Implemented Mitigation | Verification Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | S-01 | `AuthResource` | Credential stuffing and brute-force attacks against `/api/auth/login`. | Account takeover, unauthorized access to security data. | `LoginRateLimiter` enforces IP and username sliding-window counters; Argon2id password hashing via `password4j`; default admin seeded with disabled hash (`!`) requiring explicit bootstrap. | `LoginRateLimiterTest`, `AuthResourceTest` |
| **Spoofing** | S-02 | Client Session | Stolen refresh token replay across distinct browser clients. | Session hijacking. | Refresh tokens stored in Redis with one-time rotation; invalidation on password changes; Web Locks API (`auth-fetch.ts`) synchronizes token rotation across browser tabs. | `auth-fetch.test.ts`, `AuthResourceSecurityTest` |
| **Spoofing** | S-03 | `LogUploadResource` | Anonymous attacker pushes fabricated log batches into the ingestion pipeline. | False alerts, alert fatigue, audit distortion. | Endpoint restricted to authenticated roles with write access (`ANALYST`, `ADMIN`); anonymous requests rejected with HTTP 401. | `LogUploadResourceSecurityTest` |
| **Tampering** | T-01 | `LogStorageService` | Path traversal attacks via upload filenames (e.g., `../../etc/passwd`, null bytes). | Host filesystem compromise, arbitrary file overwrites. | `LogStorageService.sanitizeFileName()` strips traversal tokens (`../`, `..\`), absolute paths, and null bytes; files assigned unique UUIDs and SHA-256 hashed upon ingestion. | `LogUploadValidatorTest`, `LogStorageServiceTest` |
| **Tampering** | T-02 | Ingestion Parsers | Malformed log records deliberately crash or corrupt stream parsers. | Pipeline outage, data loss. | Safe parsing boundaries in `SyslogParser`, `AccessLogParser`, and `JsonLogParser`; strict state machine (`PENDING` -> `PROCESSING` -> `INGESTED` / `FAILED`). | `LogUploadServiceTest`, parser unit test suite |
| **Tampering** | T-03 | `OpenSearchEventSearch` | Query injection via unfiltered search parameters into OpenSearch. | Execution of unintended search queries, index corruption. | `EventQuery` generates typed JSON DSL clauses (`IpFilter`, `StatusFilter`, `Instant`); arbitrary Lucene query strings are rejected. | `OpenSearchEventSearchTest` |
| **Tampering** | T-04 | `AttackResource` | Tampered or malicious MITRE ATT&CK STIX JSON bundles imported into taxonomy. | Corruption of detection mapping and kill-chain classification. | STIX bundles validated against strict JSON schema; bundle imports restricted to `ADMIN`. | `AttackResourceTest`, `InvalidAttackBundleExceptionMapper` |
| **Repudiation** | R-01 | Identity Lifecycle | User disputes executing account creation, role changes, or credential updates. | Inability to establish forensic accountability. | `AuthEventRecorder` logs auth lifecycle events (success, failed login with known/unknown identity, logout) with client IP and timestamps to `auth_event`. | `AuthEventRecorderTest` |
| **Repudiation** | R-02 | Alert Triage | Analyst denies closing, acknowledging, or altering status of security alerts. | Unverified incident response actions. | Alert entity mutations persist modified timestamp and owner username in relational audit fields. | `AlertResourceTest` |
| **Information Disclosure** | I-01 | REST API Responses | Sensitive credentials, stack traces, or internal paths leaked in API responses. | Reconnaissance for subsequent attacks. | Sensitive fields excluded from DTO projections (`UserResponse`); comprehensive JAX-RS `ExceptionMapper` suite returns RFC7807 problem details without internal stack traces. | `UserResourceTest`, security exception mapper tests |
| **Information Disclosure** | I-02 | Cryptographic Keys | JWT private signing keys exposed in public repositories or dev bundles. | Universal forgery of session access tokens. | Asymmetric RS256 keys separated; test keys isolated in `dev-keys`; Quarkus fails fast on startup in production if signing keys are missing or insecure. | `MicroProfile Config validation` |
| **Information Disclosure** | I-03 | AI Integration | Sensitive enterprise log data leaked to external third-party LLM providers. | Regulatory violations, data privacy leakage. | LLM client isolated behind `ConfiguredChatModel`; support for on-premise local Ollama models; minimal context grounding templates. | `AlertSummaryServiceTest` |
| **Denial of Service** | D-01 | `LogUploadResource` | High-volume upload floods or decompression bombs exhausting storage and CPU. | Service degradation, server outage. | `UploadRateLimiter` enforces per-account quotas; `LogUploadValidator` rejects oversized payloads; HTTP 413 handled by `PayloadTooLargeExceptionMapper`. | `UploadRateLimiterTest` |
| **Denial of Service** | D-02 | `EventSearchResource` | Computationally expensive OpenSearch queries (large time spans, heavy aggregations). | OpenSearch cluster starvation, memory exhaustion. | Bound pagination limits, forced time range boundaries, circuit breakers via `SearchUnavailableExceptionMapper` (HTTP 503). | `EventSearchResourceTest` |
| **Denial of Service** | D-03 | Ingestion Pipeline | Message broker backpressure during log spikes. | Ingestion lag, consumer crashes. | Reactive Kafka pipeline buffers incoming events with non-blocking backpressure and consumer groups. | Kafka integration test suite |
| **Elevation of Privilege** | E-01 | RBAC Encodings | Unprivileged user (VIEWER) executes administrative actions (account mutation, attack sync). | Full administrative takeover. | Build-time `EndpointAuthorizationCoverageTest` enforces `@RolesAllowed`, `@PermitAll`, or `@Authenticated` on every JAX-RS endpoint; server-side RBAC checks on mutations. | `EndpointAuthorizationCoverageTest`, `UserResourceSecurityTest` |
| **Elevation of Privilege** | E-02 | AI Summarization | Indirect Prompt Injection within log text manipulating LLM outputs or guidance. | Misleading triage recommendations, evasion of detection. | `Grounding` pipeline enforces strict system prompt framing; post-inference validator verifies citations and IP addresses against genuine alert data; rejects ungrounded output with HTTP 502. | `GroundingTest`, `AlertSummarizerTest` |

---

## 4. In-Depth Component Analysis

### 4.1 Authentication & Credential Lifecycle (S-01, S-02, I-01)
- **Password Hashing**: Implemented via Argon2id (`password4j`). Parameters (memory cost, iterations, parallelism) encoded within the hash, allowing forward compatibility.
- **Bootstrap Security**: Initial seed migrations lock default administrator credentials with an invalid marker (`!`). Explicit bootstrapping via `AuthBootstrap` and `APP_AUTH_BOOTSTRAP_PASSWORD` is required.
- **Token Architecture**: Asymmetric RS256 JWT access tokens paired with stateful refresh tokens stored in Redis. Rotating refresh tokens invalidates previous tokens to mitigate replay windows.

### 4.2 Authorization & RBAC Enforcement (E-01)
- **Role Hierarchy**: `ADMIN` (full system mutation), `ANALYST` (triage, file upload, search), `VIEWER` (read-only search and audit inspect).
- **Compile-Time Safeguards**: `EndpointAuthorizationCoverageTest` scans JAX-RS route definitions during Maven builds. Any endpoint missing an explicit access annotation fails the build before packaging.
- **Defense in Depth**: Frontend navigation controls (`RequireAuth`, `RequirePermission`, `can()`) serve UX purposes only; all business logic independently validates caller permissions.

### 4.3 Ingestion Integrity & Sanitization (T-01, T-02, D-01)
- **File Validation**: `LogUploadValidator` checks MIME types, extensions, and byte lengths.
- **Storage Sanitization**: `LogStorageService.sanitizeFileName()` cleanses path separators and null characters before staging files.
- **Integrity Fingerprinting**: Ingestion calculates an immutable SHA-256 digest stored alongside the upload entity.

### 4.4 AI Threat Mitigations & Prompt Injection (E-02, I-03)
- **System Prompt Isolation**: Untrusted log payloads are passed as isolated data blocks rather than system directives.
- **Grounding & Anti-Hallucination**: The `Grounding` component verifies that IP addresses, file paths, and MITRE techniques output by the model exist in the source alert.
- **Deterministic Rejection**: Output failing verification is rejected immediately (HTTP 502 Bad Gateway), preventing corrupted summaries from reaching analyst triage queues.

---

## 5. Residual Risks & Future Roadmap

1. **Automated Software Composition Analysis (SCA)**:
   - *Risk*: Third-party dependencies may develop unpatched vulnerabilities.
   - *Action*: Integrate GitHub Dependabot, Snyk, or OWASP Dependency-Check into CI.
2. **Mutual TLS (mTLS) for Remote Log Forwarders**:
   - *Risk*: Direct forwarders communicating over public networks require client verification.
   - *Action*: Configure reverse proxy / ingress controller with client certificate validation (mTLS) for syslog endpoints.
3. **Multi-Factor Authentication (MFA/TOTP)**:
   - *Risk*: Credential stuffing remain effective if passwords leak externally.
   - *Action*: Add TOTP/WebAuthn second-factor authentication to `AuthResource`.
