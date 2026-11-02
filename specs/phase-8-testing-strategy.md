# VELTRIX: Phase 8 Testing Strategy — Authorized Website Vulnerability Assessment

**Document Version:** 1.0.0  
**Phase:** Phase 8 (Architecture & Planning)  
**Classification:** Quality Assurance & Security Validation  
**Status:** DRAFT / IN REVIEW  
**Authors:** VELTRIX Core Security Team  

---

## 1. Testing Philosophy & Verification Principles

The Phase 8 Vulnerability Assessment Engine involves executing live network requests, parsing potentially untrusted external payloads, and producing high-consequence security findings. A failure in testing can lead to catastrophic security regressions (e.g., SSRF into cloud metadata) or severe operational disruption to customer websites.

Testing must adhere to the following principles:
1. **Isolated Execution:** No test in the automated CI/CD pipeline shall ever issue an outbound network request to an external third-party internet domain or AWS service. All external systems, DNS servers, and targets are fully emulated using local in-process test servers.
2. **Adversarial Negative Testing:** Every security control (SSRF filter, DNS pinning, redirect guard, scope boundary, decompressor) must be exercised against comprehensive attack vector payloads.
3. **Deterministic Evidence Verification:** All tests asserting vulnerability discovery must verify that the Phase 7 `InternalEvidenceAuthority` generated a valid, verifiable cryptographic signature over the finding's `EvidenceContext`.
4. **SLO Verification:** Emergency abort operations must be deterministically benchmarked to guarantee socket teardown within the **500 ms** target SLO.

---

## 2. Test Pyramid & Coverage Requirements

```mermaid
pie title Phase 8 Test Distribution
    "Unit Tests (Domain, Scope, Rules, Scrubbing)" : 50
    "Security Attack Vector Matrix (SSRF, Rebinding, Bombs)" : 25
    "Integration Lifecycle (Register, Verify, Scan, Findings)" : 15
    "Concurrency & Abort SLO Tests" : 10
```

### Coverage Targets:
- **Security Boundary Logic (`ScopeGuard`, `SafeHttpClient`, IP filter):** **100%** statement and branch coverage.
- **Rule Evaluators (Passive & Active Analyzers):** **>95%** statement coverage.
- **API Controllers & Data Access:** **>90%** statement coverage.

---

## 3. Unit Test Suite Breakdown

### 3.1 Domain Ownership Verification Tests (`tests/unit/verification.test.ts`)
- **DNS TXT Verification:**
  - Valid TXT record containing exact tenant ID and token $\to$ returns `VERIFIED`.
  - Missing TXT record $\to$ returns `CHALLENGE_FAILED`.
  - Mismatched token or wrong organization ID $\to$ returns `CHALLENGE_FAILED`.
  - DNS resolution error or timeout $\to$ fails closed with `CHALLENGE_FAILED`.
- **HTTP Challenge Verification:**
  - Mock HTTP server returns correct JSON token at `/.well-known/veltrix-challenge/<token>` $\to$ returns `VERIFIED`.
  - Server returns 404, 500, or invalid JSON $\to$ returns `CHALLENGE_FAILED`.
  - Target URL resolves to an internal/private IP $\to$ caught by SSRF filter, returns `SSRF_BLOCKED`.
- **HTML Meta Tag Verification:**
  - HTML contains `<meta name="veltrix-site-verification" content="<token>">` $\to$ returns `VERIFIED`.
  - Missing meta tag, malformed HTML, or mismatched token $\to$ returns `CHALLENGE_FAILED`.
- **Expiry & Lifecycle Logic:**
  - Site at 80 days $\to$ active and valid for scans.
  - Site at 85 days $\to$ marked `GRACE_PERIOD`, scans blocked with `DOMAIN_VERIFICATION_SUSPENDED`.
  - Site at 91 days $\to$ marked `EXPIRED`, scans rejected with `DOMAIN_NOT_VERIFIED`.

### 3.2 Scope & Exclusion Guard Tests (`tests/unit/scope-guard.test.ts`)
- **Allowed Hosts:**
  - Request to `primaryDomain` $\to$ allowed.
  - Request to `approvedSubdomains` $\to$ allowed.
  - Request to unapproved subdomain (e.g., `attacker.example.com` or `other.com`) $\to$ rejected.
  - Port validation (permit 80, 443; reject arbitrary high ports unless whitelisted).
- **Excluded Paths:**
  - Exact match (`/logout`) $\to$ dropped.
  - Regex match (`^/admin/.*`) $\to$ dropped.
  - Query parameter edge cases (`/app?next=/logout`) $\to$ path normalized and evaluated safely.

### 3.3 Safe HTTP Transport & SSRF Filter Tests (`tests/unit/safe-http-client.test.ts`)
- Comprehensive IP Address Denylist Matrix:
  | Input | Representation | Classification | Expected Result |
  | :--- | :--- | :--- | :--- |
  | `127.0.0.1` | Standard IPv4 | Loopback | **REJECTED (`SSRF_BLOCKED`)** |
  | `127.127.127.127` | Subnet IPv4 | Loopback Range | **REJECTED (`SSRF_BLOCKED`)** |
  | `0177.0.0.1` | Octal IPv4 | Loopback | **REJECTED (`SSRF_BLOCKED`)** |
  | `0x7f.0.0.1` | Hex IPv4 | Loopback | **REJECTED (`SSRF_BLOCKED`)** |
  | `2130706433` | Dword / Integer | Loopback | **REJECTED (`SSRF_BLOCKED`)** |
  | `10.0.0.1` | Standard IPv4 | RFC 1918 Private | **REJECTED (`SSRF_BLOCKED`)** |
  | `172.16.0.1` | Standard IPv4 | RFC 1918 Private | **REJECTED (`SSRF_BLOCKED`)** |
  | `192.168.1.1` | Standard IPv4 | RFC 1918 Private | **REJECTED (`SSRF_BLOCKED`)** |
  | `169.254.169.254` | Standard IPv4 | AWS IMDS Metadata | **REJECTED (`SSRF_BLOCKED`)** |
  | `100.64.0.1` | Standard IPv4 | Carrier-Grade NAT | **REJECTED (`SSRF_BLOCKED`)** |
  | `0.0.0.0` | Standard IPv4 | Current Network | **REJECTED (`SSRF_BLOCKED`)** |
  | `::1` | IPv6 | Loopback | **REJECTED (`SSRF_BLOCKED`)** |
  | `fe80::1` | IPv6 | Link-Local | **REJECTED (`SSRF_BLOCKED`)** |
  | `fc00::1` | IPv6 | Unique Local | **REJECTED (`SSRF_BLOCKED`)** |
  | `::ffff:127.0.0.1` | IPv4-Mapped IPv6 | Loopback | **REJECTED (`SSRF_BLOCKED`)** |
  | `::ffff:169.254.169.254` | IPv4-Mapped IPv6 | AWS Metadata | **REJECTED (`SSRF_BLOCKED`)** |
  | `93.184.216.34` | Standard IPv4 | Public Internet IP | **ALLOWED** |
  | `2606:2800:220:1:248:1893:25c8:1946` | Standard IPv6 | Public Internet IP | **ALLOWED** |

### 3.4 Hop-by-Hop Redirect Tests (`tests/unit/redirects.test.ts`)
- Redirect chain: `https://site.com/start` $\to$ `https://site.com/middle` $\to$ `https://site.com/end` $\to$ followed up to 5 hops.
- Redirect loop: `A` $\to$ `B` $\to$ `A` $\to$ halts at 5 hops with `REDIRECT_LIMIT_EXCEEDED`.
- Redirect escape to AWS metadata: `https://site.com/auth` $\to$ `302 Location: http://169.254.169.254/latest/meta-data` $\to$ caught at hop 1, connection aborted, returns `SSRF_BLOCKED`.
- Cross-origin redirect escape: `https://site.com/out` $\to$ `302 Location: https://unauthorized-domain.com` $\to$ dropped by `ScopeGuard`.

### 3.5 Bounded Crawler Tests (`tests/unit/crawler.test.ts`)
- Extracts valid links from HTML `<a>`, `<form action>`, `<script src>`, `<link href>`.
- Correctly skips image, video, zip, and binary links.
- Strips URL fragments (`#section-1`) and canonicalizes query parameters (`?b=2&a=1` $\to$ `?a=1&b=2`).
- Detects crawl traps and halts at configured `maxDepth` (e.g., 3) and `maxPages` (e.g., 250).

### 3.6 Security Rule Evaluator Tests (`tests/unit/analyzers.test.ts`)
- **Passive Rule Evaluators:**
  - TLS 1.0/1.1 response $\to$ flags `TLS_WEAK_PROTOCOL` finding.
  - Missing `Content-Security-Policy` $\to$ flags `MISSING_SECURITY_HEADER` finding.
  - Cookie without `HttpOnly` or `Secure` $\to$ flags `INSECURE_COOKIE_ATTRIBUTES` finding.
  - Banner `Server: Apache/2.2.8` $\to$ flags `SERVER_VERSION_DISCLOSURE`.
- **Active Rule Evaluators:**
  - Reflected XSS Canary: Canary string reflected verbatim into HTML body $\to$ flags `CROSS_SITE_SCRIPTING_REFLECTED` (`CONFIRMED`).
  - Reflected XSS Encoded: Canary reflected as `&lt;canary&gt;` $\to$ does NOT flag (correctly avoids false positive).
  - SQL Syntax Anomaly: Injected quote causes response with `ODBC Microsoft Access Driver` error $\to$ flags `SQL_INJECTION_SYNTAX_ANOMALY` (`HIGH`).
  - Open Redirect: Injected domain reflected in `Location` header on 302 response $\to$ flags `OPEN_REDIRECT_UNVALIDATED`.

### 3.7 Secret Scrubbing & Evidence Signing Tests (`tests/unit/evidence.test.ts`)
- Request containing `Authorization: Bearer secret-token-12345` $\to$ scrubbed to `Authorization: Bearer [REDACTED]`.
- Request containing `Cookie: session=xyz; password=secret` $\to$ scrubbed to `Cookie: session=[REDACTED]; password=[REDACTED]`.
- Stored body exceeding 64 KB $\to$ truncated with `[TRUNCATED_AT_64KB]`.
- Evidence signed with `InternalEvidenceAuthority` $\to$ signature validates; tampered evidence fails signature check.

---

## 4. Adversarial Security Regression Test Suite

### 4.1 DNS Rebinding Simulation Harness (`tests/security/dns-rebinding.test.ts`)
- **Test Setup:**
  - Launch an in-process DNS server that alternates responses:
    - Query 1 for `rebind.test`: returns `198.51.100.1` (Public test IP).
    - Query 2 for `rebind.test`: returns `169.254.169.254` (Metadata IP).
- **Assertion:**
  - `SafeHttpClient` performs DNS resolution during pre-flight.
  - Socket `createConnection` connects strictly to the pinned IP (`198.51.100.1`).
  - The second DNS resolution is never triggered during connection establishment.
  - Rebinding attack is completely mitigated.

### 4.2 Decompression Bomb / Zip Bomb Harness (`tests/security/zip-bomb.test.ts`)
- **Test Setup:**
  - In-process HTTP server serves a small 10 KB gzip stream that decompresses into 500 MB of zeros.
- **Assertion:**
  - Decompression stream reader monitors byte throughput.
  - Exactly at 10 MB uncompressed threshold, stream is terminated with `STREAM_SIZE_LIMIT_EXCEEDED`.
  - Process memory remains bounded (<100 MB delta); scanner does not crash.

### 4.3 Slowloris / Hung Socket Harness (`tests/security/slowloris.test.ts`)
- **Test Setup:**
  - In-process HTTP server accepts connection, sends 1 byte of header every 5 seconds.
- **Assertion:**
  - Connection/header timeout triggers at 10 seconds.
  - Socket is destroyed (`socket.destroy()`); worker moves to next endpoint without blocking.

### 4.4 Emergency Abort Latency Benchmark (`tests/security/abort-latency.test.ts`)
- **Test Setup:**
  - Launch active scan against a mock server running 20 long-polling endpoints.
  - Issue `POST /api/v1/scans/:scanId/abort`.
- **Assertion:**
  - High-resolution timer measures duration until all sockets are closed.
  - Measured latency must be **< 500 ms**.
  - Scan status in store reflects `ABORTED`.

---

## 5. Integration Test Plan (`tests/integration/scan-lifecycle.test.ts`)

Simulates the complete enterprise workflow from asset registration to reporting:
1. `POST /api/v1/websites`: Register `test-app.local`.
2. `POST /api/v1/websites/:siteId/verification/confirm`: Verify via mock DNS TXT.
3. `POST /api/v1/scans`: Launch `STANDARD_ACTIVE` scan against local mock vulnerable server.
4. Scan worker executes crawl, runs passive analysis, executes canary active probes.
5. Findings are deduplicated, scored, and signed with `InternalEvidenceAuthority`.
6. Assert findings stored in `Veltrix-VulnerabilityFindings`:
   - 1x `CROSS_SITE_SCRIPTING_REFLECTED` (`CONFIRMED`, CVSS 7.5)
   - 1x `MISSING_SECURITY_HEADER` (`MEDIUM`, CVSS 5.0)
   - 1x `INSECURE_COOKIE_ATTRIBUTES` (`LOW`, CVSS 3.0)
7. Query `GET /api/v1/scans/:scanId/report`: Validates report structure and cryptographic verification status.
8. Assert audit log contains `SITE_REGISTERED`, `SITE_VERIFIED`, `SCAN_STARTED`, `FINDING_DISCOVERED`, and `SCAN_COMPLETED`.
