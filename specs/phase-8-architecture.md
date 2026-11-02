# VELTRIX: Phase 8 Architecture Specification — Authorized Website Vulnerability Assessment

**Document Version:** 1.1.0 (Architecture Review Hardened)  
**Phase:** Phase 8 (Architecture & Planning)  
**Classification:** System Architecture & Technical Design  
**Status:** DRAFT / IN REVIEW (PR #14 Consistency Review)  
**Authors:** VELTRIX Core Security Team  

---

## 1. System Architecture Overview

The VELTRIX Authorized Website Vulnerability Assessment Engine is designed as a modular, defense-in-depth scanning pipeline. It operates under strict authorization constraints, decoupling scan orchestration, network transport, security rule evaluation, evidence provenance, and persistent storage.

```mermaid
flowchart TD
    subgraph ControlPlane["Control Plane & API Gateway"]
        API["REST API Gateway (Express)"]
        AuthZ["RBAC Middleware (SUPER_ADMIN, ORG_ADMIN, SECURITY_ANALYST, READ_ONLY_VIEWER, AUDITOR)"]
        DomainVerifier["DomainVerificationService (DNS TXT, HTTP Challenge, Meta Tag)"]
    end

    subgraph StorageLayer["Persistence & Audit Layer"]
        DB[("Storage Engine (DynamoDB / MemoryStore)")]
        Audit[("Immutable Audit Log")]
        EvidenceAuth["InternalEvidenceAuthority (Phase 7 HMAC-SHA256 & DynamoDBReplayRegistry)"]
    end

    subgraph Orchestration["Scan Orchestration Subsystem"]
        Orchestrator["Scan Orchestrator"]
        JobQueue["Priority Scan Queue"]
        RateLimiter["Token-Bucket Rate Limiter"]
        AbortCoordinator["Emergency Abort Coordinator (500ms SLO)"]
    end

    subgraph ScannerWorker["Isolated Scanner Worker Sandbox"]
        Worker["Scan Worker Task"]
        ScopeGuard["Scope & Exclusion Guard"]
        SafeTransport["SafeHttpClient (DNS Pinning, SSRF Filter, Proxy Bypass)"]
        Crawler["Bounded HTML / Endpoint Crawler"]
        
        subgraph AnalysisPipelines["Security Analysis Pipelines"]
            PassiveChecks["Passive Security Pipeline\n(TLS, Headers, Cookies, Banners)"]
            ActiveChecks["Controlled Active Pipeline\n(XSS, SQLi Syntax, Redirect, Traversal)"]
        end

        ScoringEngine["Severity & Confidence Scoring Engine"]
        EvidenceCollector["Evidence Collector & Secret Redactor"]
    end

    subgraph TargetSystem["Target Web Application"]
        TargetApp["Authorized Target Web Server"]
    end

    %% Control Plane Flows
    API --> AuthZ
    AuthZ --> DomainVerifier
    DomainVerifier --> DB
    DomainVerifier --> Audit
    API --> Orchestrator

    %% Orchestration Flows
    Orchestrator --> JobQueue
    JobQueue --> Worker
    AbortCoordinator --> Worker
    Orchestrator --> DB

    %% Worker Execution Flows
    Worker --> ScopeGuard
    ScopeGuard --> Crawler
    Crawler --> SafeTransport
    SafeTransport --> TargetApp
    TargetApp --> SafeTransport
    SafeTransport --> PassiveChecks
    SafeTransport --> ActiveChecks

    %% Scoring & Evidence
    PassiveChecks --> ScoringEngine
    ActiveChecks --> ScoringEngine
    ScoringEngine --> EvidenceCollector
    EvidenceCollector --> EvidenceAuth
    EvidenceCollector --> DB
    EvidenceCollector --> Audit
```

---

## 2. Component Breakdown

### 2.1 Scope & Authorization Guard (`ScopeGuard`)
- **Responsibility:** Inviolable gatekeeper verifying target validity before any network operation occurs.
- **Invariants Enforced:**
  1. `site.status === 'VERIFIED'`, `!site.scanBlocked`, and `site.expiresAt > Date.now()`.
  2. If the site is in `GRACE_PERIOD`, `EXPIRED`, `SUSPENDED`, or `REVOKED`, scan dispatch is aborted immediately.
  3. Target URL scheme is strictly `http:` or `https:`.
  4. FQDN matches verified `primaryDomain` or explicitly approved entries in `approvedSubdomains`.
  5. URL path does not match any regex in `excludedPaths`.
  6. Port is explicitly permitted (default: 80, 443, 8080, 8443).

### 2.2 Hardened Safe HTTP Transport Layer (`SafeHttpClient`)
- **Responsibility:** Executes all outbound network connections with comprehensive SSRF, DNS rebinding, proxy isolation, and payload size protections.
- **Core Architecture:**
  - Built upon custom Node.js `http.Agent` and `https.Agent` overrides.
  - **Proxy Isolation Policy:** Outbound scanner traffic strictly ignores ambient `HTTP_PROXY` and `HTTPS_PROXY` environment variables by default. To prevent proxy-based SSRF bypass (where a corporate proxy performs DNS resolution and hits internal networks), scanner requests connect directly to target IP addresses.
  - **Pre-Flight DNS Resolution & IP Normalization:**
    - Resolves hostnames to all IPv4 and IPv6 addresses.
    - Normalizes numeric representations (octal `0177.0.0.1`, hex `0x7f.0.0.1`, dword `2130706433`, zero-compressed `127.1`) to canonical dotted-quad or hex IPv6.
    - Evaluates all returned addresses against strict denylists:
      - `127.0.0.0/8` (Loopback)
      - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private)
      - `169.254.0.0/16` (Link-Local & Cloud Metadata `169.254.169.254`)
      - `100.64.0.0/10` (Carrier-Grade NAT)
      - `0.0.0.0/8`, `255.255.255.255/32` (Broadcast / Current Network)
      - `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (TEST-NET)
      - `::1/128` (IPv6 Loopback), `::/128` (Unspecified)
      - `fe80::/10` (IPv6 Link-Local), `fc00::/7` (IPv6 Unique Local)
      - `::ffff:0:0/96` (IPv4-Mapped IPv6)
      - `[fd00:ec2::254]` (AWS IMDSv6 Metadata)
  - **DNS Pinning at Socket Level (TOCTOU Elimination):**
    - The `agent.createConnection(options, callback)` hook intercepts socket creation.
    - Calls `net.createConnection({ host: pinnedIp, port: options.port })`.
    - For TLS connections, wraps the connected socket using `tls.connect({ socket, servername: options.host, rejectUnauthorized: true })`.
    - Guarantees:
      1. Zero secondary DNS resolution occurs at connect time (defeats DNS rebinding).
      2. TLS SNI (`servername: options.host`) is passed so virtual hosting functions correctly.
      3. TLS certificate validation verifies that the presented certificate matches the requested hostname.
  - **Hop-by-Hop Redirect Validation:**
    - Automated redirects are disabled (`redirect: 'manual'` or `maxRedirects: 0`).
    - For any `301`, `302`, `303`, `307`, or `308` response, `Location` header is parsed and resolved.
    - Redirect target is validated through `ScopeGuard` and `SafeHttpClient` pre-flight checks before subsequent connection is permitted.
    - Maximum redirect depth is capped at 5.
  - **Stream Safeguards & Timeout Boundaries:**
    - Maximum response stream size: 10 MB (prevents memory exhaustion or decompression bombs).
    - Connection timeout: 5,000 ms.
    - Response header timeout: 10,000 ms.
    - Response body idle timeout: 15,000 ms.

### 2.3 Bounded Crawler & Endpoint Discovery Engine (`BoundedCrawler`)
- **Responsibility:** Discovers accessible web surface area without triggering destructive actions or crossing domain boundaries.
- **Design Parameters:**
  - **Traversal Algorithm:** Breadth-First Search (BFS) with configurable depth limit (default 3, max 5) and page limit (default 250, max 1000).
  - **Link Extraction:** Parses HTML `href` attributes, `<form action>` endpoints, `<script src>`, and `<link href>`.
  - **URL Normalization & Deduplication:** Removes URL fragments (`#...`), canonicalizes parameters (sorted lexicographically), strips session IDs (e.g., `jsessionid`, `phpsessid`), and tracks visited canonical URLs in a bounded set.
  - **Safety Boundaries:**
    - Issues `GET` and `HEAD` requests only.
    - Strictly forbids crawling outside `allowedHosts`.
    - Skips binary files (e.g., `.png`, `.jpg`, `.pdf`, `.zip`, `.exe`, `.mp4`).
    - Respects `robots.txt` exclusion directives when enabled in scan configuration.

### 2.4 Passive Security Analyzer (`PassiveAnalyzer`)
- **Responsibility:** Inspects server responses without sending any probing or intrusive payloads.
- **Inspection Rules:**
  1. **TLS / SSL Configuration (`RULE_PASSIVE_TLS`):**
     - TLS protocol version check (flags TLS 1.0, 1.1; verifies TLS 1.2, 1.3).
     - Certificate expiration check (flags expired or expiring within 14 days).
     - Hostname matching and certificate chain trust verification.
  2. **HTTP Security Headers (`RULE_PASSIVE_HEADERS`):**
     - `Strict-Transport-Security` (HSTS): Verifies presence, `max-age >= 31536000`, `includeSubDomains`.
     - `Content-Security-Policy` (CSP): Flags missing header, `unsafe-inline`, `unsafe-eval`, or wildcard `*` origins.
     - `X-Frame-Options`: Verifies `DENY` or `SAMEORIGIN` (mitigates clickjacking).
     - `X-Content-Type-Options`: Verifies `nosniff`.
     - `Referrer-Policy`: Verifies restrictive policy (e.g., `strict-origin-when-cross-origin`).
     - `Permissions-Policy`: Verifies camera, microphone, geolocation restrictions.
  3. **Cookie Security Attributes (`RULE_PASSIVE_COOKIES`):**
     - Inspects all `Set-Cookie` headers for `Secure`, `HttpOnly`, and `SameSite` (`Lax`/`Strict`).
  4. **Information Disclosure & Banner Leakage (`RULE_PASSIVE_DISCLOSURE`):**
     - Flags revealing server banners (`Server: Apache/2.4.1`, `X-Powered-By: PHP/7.4`).
     - Flags exposed debug endpoints, stack traces, `.git/HEAD`, `.env`.

### 2.5 Controlled Active Security Analyzer (`ActiveAnalyzer`)
- **Responsibility:** Executes controlled, benign active probes against discovered endpoints.
- **Strict Non-Destructive Invariant:** No modification of database records, no deletion of files, no state alteration.
- **Probe Plugins:**
  1. **Reflected XSS Canary Check (`RULE_ACTIVE_XSS_CANARY`):**
     - Generates an inert, non-executable alphanumeric canary: `vltxcanary_<random16Hex>`.
     - Appends canary to query parameters.
     - Inspects response body to see if the canary is reflected verbatim without proper HTML/attribute entity escaping.
     - Status code check is insufficient; reflection context (HTML body, script block, attribute) is analyzed.
  2. **SQL Syntax Anomaly Check (`RULE_ACTIVE_SQLI_ANOMALY`):**
     - Appends benign syntax disruptor tokens (`'`, `"`, `''`) to numeric or string parameters.
     - Compares baseline response vs probe response.
     - Searches response body for known RDBMS syntax error signatures (MySQL, PostgreSQL, Oracle, SQLite, MSSQL).
     - Does NOT attempt data exfiltration, blind sleep loops, or boolean injection.
  3. **Open Redirect Canary Check (`RULE_ACTIVE_OPEN_REDIRECT`):**
     - Supplies canary parameter `redirect=https://example.com/vltx_canary`.
     - Checks if response is `301`/`302`/`307`/`308` and `Location` header points to `example.com/vltx_canary`.
  4. **Path Traversal Canary Check (`RULE_ACTIVE_PATH_TRAVERSAL`):**
     - Supplies non-sensitive traversal probe (e.g., `../../../../etc/nonexistent_canary_probe`).
     - Detects characteristic error messages indicating path processing flaws without leaking sensitive system files.

### 2.6 Severity & Confidence Scoring Engine (`ScoringEngine`)
- **Responsibility:** Computes standardized risk metrics for all discovered findings.
- **Scoring Dimensions:**
  - **Base Severity:** `CRITICAL` (CVSS 9.0–10.0), `HIGH` (CVSS 7.0–8.9), `MEDIUM` (CVSS 4.0–6.9), `LOW` (CVSS 0.1–3.9), `INFORMATIONAL` (CVSS 0.0).
  - **Confidence Tier:**
    - `CONFIRMED`: Verifiable canary reflection or cryptographic mismatch.
    - `HIGH`: Deterministic error signature matched with differential response verification.
    - `MEDIUM`: Header anomaly or heuristic indicator without execution proof.
    - `LOW`: Heuristic match with possible false positive indicators.
- **False-Positive Suppression:**
  - Requires differential baseline comparison (e.g., parameter reflection must not have been present in the baseline request).
  - Status code changes alone (e.g., 500 Internal Server Error) are marked `LOW` confidence unless corroborated by an explicit syntax error signature.

### 2.7 Evidence Aggregator & Provenance Signer (`EvidenceSigner`)
- **Responsibility:** Constructs tamper-evident proof for every finding, integrating with Phase 7 `InternalEvidenceAuthority`.
- **Evidence Lifecycle:**
  1. Sanitizes request/response pair (strips passwords, Authorization headers, session cookies, API keys).
  2. Generates sanitized reproduction curl command with credentials redacted.
  3. Truncates response body to maximum 64 KB.
  4. Computes SHA-256 hash of raw target payload and raw response body.
  5. Obtains an authenticated `InternalTrustedEvidenceContext` by calling `InternalEvidenceAuthority.prototype.createContext()`:
     ```typescript
     const trustedContext = authority.createContext({
       serviceAuthToken: process.env.VELTRIX_AUTH_CORE_SCANNER!,
       verifierIdentity: 'core-scanner:active-audit',
       provenance: 'TRUSTED_SERVER_COMPONENT',
       eventId: findingId,
       orgId: site.orgId,
       siteId: site.siteId,
       verifiedSignalIdentifiers: [signalIdentifier],
       evidenceReferences: [reproductionCurlHash],
       verifiedResponseEvidence: {
         responseBody: sanitizedSnippet,
         errorMessage: detectedSyntaxError,
       },
     });
     ```
  6. Stores cryptographic signature and provenance context alongside finding record in DynamoDB table `Veltrix-VulnerabilityFindings`.

### 2.8 Scan Orchestration & Emergency Abort Engine (`ScanOrchestrator`)
- **Responsibility:** Coordinates scan execution, enforces concurrency ceilings, and handles emergency stops.
- **Concurrency & Rate Controls:**
  - Per-target rate limiting: Token-bucket algorithm with configurable RPS (default 5, max 20).
  - Concurrency limits: 1 scan per website, 3 scans per organization.
- **Emergency Abort Protocol (500 ms SLO):**
  1. API receives `POST /api/v1/scans/:scanId/abort` OR site verification is revoked via `POST /api/v1/websites/:siteId/revoke`.
  2. Updates scan job record in DynamoDB with `status = 'ABORT_REQUESTED'`.
  3. Abort coordinator signals the active worker's `AbortController`.
  4. Active HTTP client immediately destroys all pending and active sockets (`socket.destroy()`).
  5. Worker drains pending queues and persists findings gathered up to the abort timestamp.
  6. Scan status transitions to `ABORTED`.
  7. If worker does not acknowledge within 10 seconds, coordinator force-terminates the worker task and sets status to `ABORT_FAILED_TIMED_OUT`.

---

## 3. End-to-End Scan Execution Flow

```mermaid
sequenceDiagram
    autonumber
    actor Admin as ORG_ADMIN / SUPER_ADMIN
    participant API as Scan API
    participant Guard as Scope & Auth Guard
    participant DB as DynamoDB / MemoryStore
    participant Orch as Scan Orchestrator
    participant Worker as Scan Worker
    participant Transport as SafeHttpClient
    participant Target as Target Web Server
    participant Auth as Phase 7 EvidenceAuthority

    Admin->>API: POST /api/v1/scans (siteId, profile, scope)
    API->>Guard: Validate site ownership & authorization
    Guard->>DB: Query site verification record
    DB-->>Guard: Status=VERIFIED, scanBlocked=false, expiresAt > now
    Guard-->>API: Authorization Valid
    API->>DB: Create ScanJob (status=QUEUED)
    API-->>Admin: 202 Accepted (scanId)

    Orch->>DB: Claim QUEUED scan job
    Orch->>Worker: Dispatch scan execution
    Worker->>DB: Update ScanJob (status=RUNNING)

    loop Crawl & Assessment Phase
        Worker->>Transport: Request URL (GET /path)
        Transport->>Transport: DNS Pre-flight & Pinning (SSRF Check, Proxy Bypass)
        Transport->>Target: TCP Connect to Pinned Public IP
        Target-->>Transport: HTTP Response (Status, Headers, Body)
        Transport->>Transport: Validate Stream (<10MB) & Check Redirects
        Transport-->>Worker: Safe HttpResponse

        Worker->>Worker: Run Passive Checks (TLS, Headers, Cookies)
        Worker->>Worker: Run Active Checks (Benign Canaries)

        opt Finding Discovered
            Worker->>Worker: Compute CVSS & Confidence Tier
            Worker->>Worker: Redact Secrets from Headers & Reproduction Curl
            Worker->>Auth: createContext(serviceAuthToken, 'core-scanner:active-audit')
            Auth-->>Worker: Signed InternalTrustedEvidenceContext
            Worker->>DB: Save Finding (Veltrix-VulnerabilityFindings)
        end
    end

    Worker->>DB: Update ScanJob (status=COMPLETED, metrics)
    Worker->>DB: Log Audit Event (SCAN_COMPLETED)
```

---

## 4. Integration with Existing VELTRIX Components

| Component | Integration Touchpoint | Technical Mechanism |
| :--- | :--- | :--- |
| **`StorageInterface`** | Data persistence for assets, scans, findings | Implemented across both `DynamoDBStore` (AWS) and `MemoryStore` (isolated tests). |
| **`InternalEvidenceAuthority`** | Evidence authenticity & non-repudiation | Issues HMAC-SHA256 signatures for findings using approved verifier `'core-scanner:active-audit'` and credential `VELTRIX_AUTH_CORE_SCANNER`. |
| **`AuditLog`** | Tamper-evident compliance tracking | Emits structured audit events for `WEBSITE_REGISTERED`, `WEBSITE_VERIFIED`, `WEBSITE_REVOKED`, `SCAN_STARTED`, `SCAN_ABORTED`, and `SCAN_COMPLETED`. |
| **`EventService` / Detections** | Real-time correlation with live attacks | Vulnerability findings correlated with real-time detection telemetry via `siteId` and endpoint path. |
| **`jwtService` / `requireRole`** | Authentication & RBAC | Enforces canonical production roles: `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_VIEWER`, and `AUDITOR`. |
