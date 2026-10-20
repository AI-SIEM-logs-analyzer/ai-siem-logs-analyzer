# OWASP Top 10 Security Assessment & Verification

This document details the security evaluation of the **AI SIEM Logs Analyzer** against the **OWASP Top 10 (2021)** standard.

---

## Executive Summary

| Category | Description | Status | Key Mechanism |
| :--- | :--- | :--- | :--- |
| **A01:2021** | Broken Access Control | **PASS** | Automated build-time RBAC test (`EndpointAuthorizationCoverageTest`), role-based endpoint security, path traversal sanitization |
| **A02:2021** | Cryptographic Failures | **PASS** | Argon2id hashing via `password4j`, locked default credentials (`!`), asymmetric RS256 JWT, zero secret leaks |
| **A03:2021** | Injection | **PASS** | ORM parameter binding, typed OpenSearch query DSL, LLM Grounding validation |
| **A04:2021** | Insecure Design | **PASS** | IP/account-level rate limiting (`LoginRateLimiter`, `UploadRateLimiter`), upload lifecycle state machine, Web Locks session coordination |
| **A05:2021** | Security Misconfiguration | **PASS** | Fail-fast config validation, comprehensive custom JAX-RS `ExceptionMapper` suite preventing trace leaks |
| **A06:2021** | Vulnerable and Outdated Components | **AUDITED** | Up-to-date dependency tree on Quarkus 3.x and React 19; CI SCA scanning recommended |
| **A07:2021** | Identification and Authentication Failures | **PASS** | Session revocation upon password changes, immediate refresh token invalidation on logout, open-redirect sanitization |
| **A08:2021** | Software and Data Integrity Failures | **PASS** | SHA-256 upload verification, safe parser error boundary handling, MITRE STIX JSON validation |
| **A09:2021** | Security Logging and Monitoring Failures | **PASS** | Authentication event recording (`AuthEventRecorder`), microprofile readiness/liveness health checks |
| **A10:2021** | Server-Side Request Forgery (SSRF) | **PASS** | No user-controlled remote URI retrieval; fixed backend configuration for upstream AI and OpenSearch connections |

---

## Detailed Evaluation by Category

### A01:2021 – Broken Access Control

#### Status: PASS

#### Architecture & Mechanisms
1. **Server-Side Role-Based Access Control (RBAC)**:
   - System roles are defined in `com.siem.analyzer.domain.Role`: `ADMIN`, `ANALYST`, `VIEWER`.
   - Access control is verified by `EndpointAuthorizationCoverageTest`, which inspects compiled endpoint methods at build time and fails the build if any REST route lacks explicit security annotations (`@RolesAllowed`, `@PermitAll`, or `@Authenticated`).
   - Endpoint enforcement matrix:
     - `UserResource`: Mutations (`create`, `update`, `delete`, `changePassword`) restricted to `ADMIN`. Read operations (`list`, `get`) permit authenticated roles (`ADMIN`, `ANALYST`, `VIEWER`) so analysts can assign ownership during triage.
     - `AttackResource`: ATT&CK dataset imports restricted to `ADMIN`. Read-only taxonomy endpoints (`tactics`, `techniques`) accessible to all authenticated users.
     - `LogUploadResource`: File uploads restricted to `ANALYST` and `ADMIN`. `VIEWER` access is strictly read-only.
     - `AlertResource`: Triage state mutations and AI summarization restricted to `ANALYST` and `ADMIN`.
2. **Directory & Path Traversal Prevention**:
   - `LogStorageService.sanitizeFileName()` sanitizes incoming upload filenames, removing directory traversal tokens (`../`, `..\\`), absolute paths, and null bytes before writing to the storage directory.
3. **Frontend Guard Rails**:
   - React router and UI components enforce view-level permissions using `RequireAuth`, `RequirePermission`, and the `can()` helper function.

---

### A02:2021 – Cryptographic Failures

#### Status: PASS

#### Architecture & Mechanisms
1. **Password Storage**:
   - Implemented via Argon2id through `password4j`, configured in `AppConfig.Argon2Settings` with configurable memory (`memoryKib`), iterations, parallelism, salt length, and hash length.
   - Argon2id parameters are encoded into the hash strings, enabling transparent parameter upgrades over time without invalidating existing passwords.
2. **Locked Default Credentials**:
   - The initial database migration seeds the default `admin` account with an invalid hash marker (`!`), preventing default or hardcoded credential exploitation.
   - An explicit bootstrap password (`APP_AUTH_BOOTSTRAP_PASSWORD`) must be supplied via `AuthBootstrap` during initial deployment.
3. **Token Signatures & Asymmetric Cryptography**:
   - Access tokens use asymmetric RS256 JWT signatures. The private signing key remains isolated on the backend.
   - Development keys (`dev-keys`) are restricted to local test environments; production deployments fail at startup if required signing keys are omitted.
4. **Data Masking**:
   - Internal credentials and password hashes are excluded from API DTOs (e.g., `UserResponse`).

---

### A03:2021 – Injection

#### Status: PASS

#### Architecture & Mechanisms
1. **SQL / HQL Injection**:
   - All persistence queries across repositories (`UserRepository`, `AlertRepository`, `LogEventRepository`, `LogUploadRepository`) utilize Hibernate Panache with bound parameters. Zero dynamic SQL string concatenations exist.
2. **Search Engine Query Injection (OpenSearch)**:
   - `OpenSearchEventSearch` and `EventQuery` generate JSON DSL queries with typed filters (`IpFilter`, `StatusFilter`, `Severity`, `Instant`).
   - Arbitrary Lucene query string inputs are not accepted from clients, neutralizing search query injection attacks.
3. **LLM Prompt Injection**:
   - `Grounding` establishes prompt boundary separation: fixed system instructions remain isolated from untrusted log/alert JSON payloads.
   - Post-inference validation verifies evidence quotes and IP addresses against original alert attributes; hallucinated or injected claims cause HTTP 502 rejection.
4. **Parser Input Bounds**:
   - `SyslogParser`, `AccessLogParser`, and `JsonLogParser` validate input structure and length, safely rejecting malformed lines without throwing unhandled exceptions.

---

### A04:2021 – Insecure Design

#### Status: PASS

#### Architecture & Mechanisms
1. **Rate Limiting**:
   - `LoginRateLimiter`: Enforces per-IP and per-account failure counters. Exceeding thresholds results in HTTP 429 (`RateLimitedException`) with a `Retry-After` header. State clears upon valid credential authentication.
   - `UploadRateLimiter`: Enforces per-account rate limits on log ingestion endpoints to prevent resource exhaustion attacks.
2. **Upload State Machine**:
   - `LogUploadService` enforces strict state transitions (`PENDING` → `PROCESSING` → `INGESTED` / `FAILED`).
   - Out-of-order transitions trigger `IllegalUploadTransitionException`.
3. **Cross-Tab Concurrency Control**:
   - The frontend API client (`auth-fetch.ts`) utilizes the Web Locks API (`navigator.locks`) to synchronize token rotation across multiple tabs sharing local storage, preventing race conditions and false token reuse alerts.

---

### A05:2021 – Security Misconfiguration

#### Status: PASS

#### Architecture & Mechanisms
1. **Exception Sanitization**:
   - Dedicated JAX-RS `ExceptionMapper` components sanitize error responses and prevent internal stack trace leakage:
     - `AuthExceptionMapper` (401 / 403)
     - `RateLimitedExceptionMapper` (429)
     - `PayloadTooLargeExceptionMapper` (413)
     - `SearchUnavailableExceptionMapper` (503)
     - `DuplicateUserExceptionMapper` (409)
     - `UploadRateLimitedExceptionMapper` (429)
     - `UnsupportedLogFileExceptionMapper` (415)
     - `InvalidAttackBundleExceptionMapper` (400)
2. **Configuration Hardening**:
   - MicroProfile Config profiles strictly separate `dev`, `test`, and `prod` properties.
   - Docker container images are assembled via Google Jib, running unprivileged non-root service accounts.

---

### A06:2021 – Vulnerable and Outdated Components

#### Status: AUDITED

#### Architecture & Mechanisms
1. **Dependency Governance**:
   - Modern framework stack: Quarkus 3.x, React 19, TypeScript, and Vite.
   - Parsing dependencies (Yauaa, password4j, Jackson) are pinned to recent releases.
2. **Actionable Recommendations**:
   - Integrate automated Software Composition Analysis (SCA) in CI (e.g., GitHub Dependabot, Snyk, or OWASP Dependency-Check Maven plugin).

---

### A07:2021 – Identification and Authentication Failures

#### Status: PASS

#### Architecture & Mechanisms
1. **Authentication Lifecycle**:
   - Managed via `AuthResource` and `AuthService` (`/api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`, `/api/auth/me`).
2. **Session Invalidation**:
   - User password changes immediately revoke active refresh tokens and sessions (`UserService.changePassword()`).
   - Logging out explicitly revokes the refresh token record.
3. **Open Redirect Mitigation**:
   - The frontend login page sanitizes post-login redirect targets using `safeRedirect()`, ensuring navigation remains restricted to internal relative paths.

---

### A08:2021 – Software and Data Integrity Failures

#### Status: PASS

#### Architecture & Mechanisms
1. **File Upload Verification**:
   - `LogUploadValidator` verifies file size limits, content types, extensions, and empty streams.
   - Files are hashed with SHA-256 upon ingestion (`storesInputStreamAndComputesChecksum`) to establish an immutable integrity record.
2. **Safe Deserialization**:
   - JSON parsing via Jackson avoids polymorphic default typing vulnerabilities (`enableDefaultTyping` disabled).
   - MITRE STIX JSON bundles are validated against expected schemas before database synchronization (`InvalidAttackBundleExceptionMapper`).

---

### A09:2021 – Security Logging and Monitoring Failures

#### Status: PASS

#### Architecture & Mechanisms
1. **Audit Event Tracking**:
   - `AuthEventRecorder` records authentication milestones (successful login, failed login with known or unknown username, logout) with client IP and timestamps.
2. **Health Endpoints**:
   - `AppReadinessCheck` and `SearchIndexHealthCheck` expose health metrics via standard MicroProfile health endpoints (`/q/health/ready`, `/q/health/live`).
3. **Audit Trails**:
   - Triage operations (alert status transitions and assignment) retain an auditable record of the responsible user and timestamp.

---

### A10:2021 – Server-Side Request Forgery (SSRF)

#### Status: PASS

#### Architecture & Mechanisms
1. **Absence of User-Supplied Remote Fetching**:
   - No REST endpoints accept user-defined URLs for server-side fetching.
   - Log ingestion is strictly push-based (HTTP multipart upload or direct syslog listener).
2. **Hardened Upstream Integration**:
   - Upstream service connections (OpenSearch cluster and AI LLM providers such as OpenAI, Anthropic, Ollama) are configured statically through server-side properties, isolated from user inputs.

---

## Conclusion

The AI SIEM Logs Analyzer architecture exhibits comprehensive defensive security engineering across all ten OWASP Top 10 categories, highlighted by automated build-time authorization verification (`EndpointAuthorizationCoverageTest`), Argon2id credential hashing with locked bootstrap accounts, strict parameter binding, rate limiting, and defensive exception handling.
