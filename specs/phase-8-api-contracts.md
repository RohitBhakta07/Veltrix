# VELTRIX: Phase 8 API Contracts Specification — Authorized Website Vulnerability Assessment

**Document Version:** 1.1.0 (Architecture Review Hardened)  
**Phase:** Phase 8 (Architecture & Planning)  
**Classification:** REST API Contracts & Data Transfer Objects (DTOs)  
**Status:** DRAFT / IN REVIEW (PR #14 Consistency Review)  
**Authors:** VELTRIX Core Security Team  

---

## 1. Authentication & Common Protocol Standards

All Phase 8 endpoints adhere strictly to VELTRIX platform-wide conventions:
- **Base URI:** `/api/v1`
- **Transport Security:** Strict TLS 1.3 / 1.2 required.
- **Authentication:** Bearer JWT required in the `Authorization` header (`Authorization: Bearer <jwt>`).
- **Tenant Context:** Inferred strictly from validated JWT claims (`orgId`, `userId`, `role`).
- **Standard Envelope:** Responses wrap data in `ApiResponse<T>`:
  ```json
  {
    "success": true,
    "data": {},
    "meta": {
      "timestamp": "2026-11-02T12:00:00.000Z",
      "requestId": "req-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c"
    }
  }
  ```
- **Standard Error Envelope:** Errors wrap details in `ApiErrorResponse`:
  ```json
  {
    "success": false,
    "error": {
      "code": "ERROR_CODE_STRING",
      "message": "Human-readable explanation of error.",
      "details": {},
      "requestId": "req-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c"
    }
  }
  ```
- **Canonical RBAC Roles:**
  - `SUPER_ADMIN` / `ORG_ADMIN`: Full administrative control (register, verify, revoke, deep scans, delete).
  - `SECURITY_ANALYST`: Operational control (passive scans, standard active scans, abort, triage findings).
  - `READ_ONLY_VIEWER` / `AUDITOR`: Read-only visibility (list assets, view scans, inspect findings, export reports).

---

## 2. Website Asset & Verification Endpoints

### 2.1 Register Website Asset (`POST /api/v1/websites`)
Registers a target domain under the caller's organization and automatically generates challenge tokens.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`.
- **Request Body:**
  ```json
  {
    "name": "Production Customer Portal",
    "primaryDomain": "portal.example.com",
    "approvedSubdomains": ["api-portal.example.com", "auth-portal.example.com"],
    "environment": "PRODUCTION",
    "riskTier": "HIGH",
    "tags": ["ecommerce", "pci-scope"]
  }
  ```
- **Response 201 Created:**
  ```json
  {
    "success": true,
    "site": {
      "siteId": "site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
      "orgId": "org-enterprise-01",
      "name": "Production Customer Portal",
      "primaryDomain": "portal.example.com",
      "approvedSubdomains": ["api-portal.example.com", "auth-portal.example.com"],
      "environment": "PRODUCTION",
      "riskTier": "HIGH",
      "status": "PENDING_VERIFICATION",
      "scanBlocked": true,
      "verificationToken": "vltx_tok_9b2a7d4e1f8c3a5b6d7e8f0a1b2c3d4e",
      "dnsTxtRecord": {
        "host": "_veltrix-challenge.portal.example.com",
        "value": "veltrix-verify=org-enterprise-01.vltx_tok_9b2a7d4e1f8c3a5b6d7e8f0a1b2c3d4e"
      },
      "httpChallenge": {
        "url": "https://portal.example.com/.well-known/veltrix-challenge/vltx_tok_9b2a7d4e1f8c3a5b6d7e8f0a1b2c3d4e",
        "expectedBody": {
          "veltrixChallengeToken": "vltx_tok_9b2a7d4e1f8c3a5b6d7e8f0a1b2c3d4e",
          "orgId": "org-enterprise-01"
        }
      },
      "tags": ["ecommerce", "pci-scope"],
      "createdAt": "2026-11-02T12:00:00.000Z",
      "updatedAt": "2026-11-02T12:00:00.000Z"
    }
  }
  ```
- **Error Codes:**
  - `400 VALIDATION_ERROR`: Invalid parameters or prohibited domain format.
  - `409 DOMAIN_ALREADY_CLAIMED`: Domain is already claimed by another organization.

---

### 2.2 List Website Assets (`GET /api/v1/websites`)
Retrieves website assets owned by the tenant.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_VIEWER`, `AUDITOR`.
- **Query Parameters:** `status` (optional), `limit` (default 50), `cursor` (optional).
- **Response 200 OK:**
  ```json
  {
    "success": true,
    "total": 1,
    "sites": [
      {
        "siteId": "site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
        "orgId": "org-enterprise-01",
        "name": "Production Customer Portal",
        "primaryDomain": "portal.example.com",
        "status": "VERIFIED",
        "scanBlocked": false,
        "environment": "PRODUCTION",
        "riskTier": "HIGH",
        "verifiedAt": "2026-11-02T12:15:00.000Z",
        "expiresAt": "2027-01-31T12:15:00.000Z"
      }
    ],
    "meta": {
      "timestamp": "2026-11-02T12:16:00.000Z",
      "cursor": null,
      "hasMore": false
    }
  }
  ```

---

### 2.3 Confirm Domain Ownership Verification (`POST /api/v1/websites/:siteId/verify`)
Executes the domain verification check using the selected challenge method.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`.
- **Request Body:**
  ```json
  {
    "method": "DNS_TXT"
  }
  ```
  *(Permitted methods: `DNS_TXT` | `HTTP_CHALLENGE` | `META_TAG`)*
- **Response 200 OK (Verification Successful):**
  ```json
  {
    "success": true,
    "verified": true,
    "status": "VERIFIED",
    "verifiedAt": "2026-11-02T12:15:00.000Z",
    "expiresAt": "2027-01-31T12:15:00.000Z",
    "message": "Domain 'portal.example.com' successfully verified via DNS_TXT."
  }
  ```
- **Error Codes:**
  - `400 CHALLENGE_VERIFICATION_FAILED`: DNS record or HTTP challenge file missing or mismatched.
  - `404 WEBSITE_NOT_FOUND`: Specified siteId does not exist for this organization.
  - `429 VERIFICATION_RATE_LIMITED`: Maximum verification attempts (5 per 15 min) exceeded.

---

### 2.4 Revoke Domain Verification (`POST /api/v1/websites/:siteId/revoke`)
Revokes domain verification and places asset into `GRACE_PERIOD` with immediate scan freeze.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`.
- **Request Body:**
  ```json
  {
    "reason": "Administrative revocation due to DNS migration."
  }
  ```
- **Response 200 OK:**
  ```json
  {
    "success": true,
    "site": {
      "siteId": "site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
      "status": "GRACE_PERIOD",
      "scanBlocked": true,
      "gracePeriodEndsAt": "2026-11-09T12:20:00.000Z"
    },
    "message": "Website 'site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c' verification revoked. Asset placed in GRACE_PERIOD with immediate scan freeze."
  }
  ```

---

### 2.5 Delete Website Asset (`DELETE /api/v1/websites/:siteId`)
Deletes asset and releases the atomic domain ownership lock.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`.
- **Response 200 OK:**
  ```json
  {
    "success": true,
    "message": "Website asset 'site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c' successfully deleted."
  }
  ```

---

## 3. Vulnerability Scanning Endpoints

### 3.1 Launch Vulnerability Scan (`POST /api/v1/scans`)
Dispatches a new vulnerability assessment job.
- **RBAC:**
  - `PASSIVE_BASELINE`: `SECURITY_ANALYST`, `ORG_ADMIN`, `SUPER_ADMIN`.
  - `STANDARD_ACTIVE`: `SECURITY_ANALYST`, `ORG_ADMIN`, `SUPER_ADMIN`.
  - `DEEP_ASSESSMENT`: `SUPER_ADMIN`, `ORG_ADMIN` strictly required.
- **Request Body:**
  ```json
  {
    "siteId": "site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
    "scanProfile": "STANDARD_ACTIVE",
    "scope": {
      "targetUrl": "https://portal.example.com",
      "includeSubdomains": true,
      "maxDepth": 3,
      "maxPages": 250,
      "excludedPaths": ["^/auth/logout$", "^/admin/users/delete/.*"]
    },
    "rateLimitRps": 5
  }
  ```
- **Validation Rules:**
  - `siteId` must exist, belong to tenant, and have `status === 'VERIFIED'`, `!scanBlocked`, and `expiresAt > Date.now()`.
  - `scope.targetUrl` must resolve to `primaryDomain` or approved subdomains.
  - `rateLimitRps`: Integer between 1 and 20.
- **Response 202 Accepted:**
  ```json
  {
    "success": true,
    "data": {
      "scanId": "scan-018d5f31-74e1-7cb2-b43a-e9fa651f8b1d",
      "orgId": "org-enterprise-01",
      "siteId": "site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
      "scanProfile": "STANDARD_ACTIVE",
      "status": "QUEUED",
      "scope": {
        "targetUrl": "https://portal.example.com",
        "includeSubdomains": true,
        "maxDepth": 3,
        "maxPages": 250,
        "excludedPaths": ["^/auth/logout$", "^/admin/users/delete/.*"]
      },
      "rateLimitRps": 5,
      "queuedAt": "2026-11-02T13:00:00.000Z"
    }
  }
  ```
- **Error Codes:**
  - `403 DOMAIN_NOT_VERIFIED`: Domain is unverified, expired, or has `scanBlocked: true`.
  - `403 DOMAIN_VERIFICATION_SUSPENDED`: Site is in grace period; re-verification required before scanning.
  - `400 TARGET_OUT_OF_SCOPE`: Target URL does not match verified domain or approved subdomains.
  - `409 SCAN_ALREADY_RUNNING`: Another scan is currently active on this website asset.
  - `429 CONCURRENT_SCAN_LIMIT_REACHED`: Tenant has reached maximum active scan ceiling (3).

---

### 3.2 List Scans (`GET /api/v1/scans`)
Retrieves scan history.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_VIEWER`, `AUDITOR`.
- **Query Parameters:** `siteId` (optional), `status` (optional), `limit` (default 20), `cursor` (optional).
- **Response 200 OK:**
  ```json
  {
    "success": true,
    "data": {
      "scans": [
        {
          "scanId": "scan-018d5f31-74e1-7cb2-b43a-e9fa651f8b1d",
          "siteId": "site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
          "scanProfile": "STANDARD_ACTIVE",
          "status": "COMPLETED",
          "queuedAt": "2026-11-02T13:00:00.000Z",
          "startedAt": "2026-11-02T13:00:02.000Z",
          "completedAt": "2026-11-02T13:04:15.000Z",
          "metrics": {
            "pagesCrawled": 84,
            "requestsSent": 412,
            "findingsCount": 3
          }
        }
      ],
      "nextCursor": null
    }
  }
  ```

---

### 3.3 Get Scan Details & Progress (`GET /api/v1/scans/:scanId`)
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_VIEWER`, `AUDITOR`.
- **Response 200 OK:** Returns detailed execution progress, phase (`CRAWLING`, `PASSIVE_CHECKS`, `ACTIVE_CHECKS`), and counters.

---

### 3.4 Emergency Abort Scan (`POST /api/v1/scans/:scanId/abort`)
Signals active worker to immediately terminate all active network connections. Target SLO: 500 ms.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`.
- **Request Body:**
  ```json
  {
    "reason": "Operator requested manual emergency stop during production deployment."
  }
  ```
- **Response 200 OK (Abort Acknowledged):**
  ```json
  {
    "success": true,
    "data": {
      "status": "ABORTED",
      "scanId": "scan-018d5f31-74e1-7cb2-b43a-e9fa651f8b1d",
      "abortedAt": "2026-11-02T13:02:11.450Z",
      "abortedBy": "user-soc-analyst-02",
      "completedRequests": 184,
      "message": "Scan worker acknowledged emergency stop signal and closed active connections."
    }
  }
  ```

---

## 4. Vulnerability Findings & Reporting Endpoints

### 4.1 List Findings (`GET /api/v1/findings` or `GET /api/v1/scans/:scanId/findings`)
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_VIEWER`, `AUDITOR`.
- **Query Parameters:** `siteId`, `severity`, `status` (`OPEN`, `RESOLVED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`), `limit`, `cursor`.
- **Response 200 OK:** Returns paginated list of findings.

---

### 4.2 Get Finding Details & Evidence (`GET /api/v1/findings/:findingId`)
Retrieves comprehensive technical finding details, raw sanitized evidence, and cryptographic provenance signature.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_VIEWER`, `AUDITOR`.
- **Response 200 OK:**
  ```json
  {
    "success": true,
    "data": {
      "findingId": "find-018d5f32-74e1-7cb2-b43a-e9fa651f8b1e",
      "scanId": "scan-018d5f31-74e1-7cb2-b43a-e9fa651f8b1d",
      "siteId": "site-018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
      "vulnerabilityType": "CROSS_SITE_SCRIPTING_REFLECTED",
      "title": "Reflected Cross-Site Scripting (XSS) in Search Query Parameter",
      "severity": "HIGH",
      "cvssScore": 7.5,
      "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
      "confidence": "CONFIRMED",
      "status": "OPEN",
      "description": "The search query parameter 'q' reflects user input into the HTML body without proper sanitization or context-aware encoding.",
      "remediation": "Apply context-aware HTML entity encoding on all user input reflected in server-side templates or implement a strict Content-Security-Policy.",
      "evidence": {
        "targetUrl": "https://portal.example.com/search?q=vltxcanary_7a9f2",
        "method": "GET",
        "requestHeaders": {
          "User-Agent": "Veltrix-Security-Scanner/1.0",
          "Accept": "text/html",
          "Authorization": "[REDACTED]"
        },
        "responseStatus": 200,
        "responseHeaders": {
          "Content-Type": "text/html; charset=utf-8",
          "Server": "nginx/1.22.1",
          "Set-Cookie": "[REDACTED]"
        },
        "canaryPayload": "vltxcanary_7a9f2",
        "responseBodySnippet": "<div class=\"results\">Search query: vltxcanary_7a9f2</div>",
        "reproductionCurl": "curl -i -s 'https://portal.example.com/search?q=vltxcanary_7a9f2' -H 'Authorization: [REDACTED]'",
        "timestamp": "2026-11-02T13:02:10.150Z"
      },
      "provenance": {
        "version": "VELTRIX_EVIDENCE_V2",
        "verifierIdentity": "core-scanner:active-audit",
        "verifiedProvenance": "TRUSTED_SERVER_COMPONENT",
        "verifiedSignalIdentifiers": ["CANARY_TOKEN_BREACH"],
        "authoritySignature": "3a8f9c4d2e1b7a0f6c5d4e3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f",
        "verified": true
      }
    }
  }
  ```

---

### 4.3 Update Finding Status (`PATCH /api/v1/findings/:findingId`)
Allows analysts to triage findings.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`.
- **Request Body:**
  ```json
  {
    "status": "FALSE_POSITIVE",
    "justification": "Input is encoded via client-side DOMPurify before DOM insertion; reflection in HTML is inert."
  }
  ```
  *(Permitted statuses: `OPEN` | `RESOLVED` | `FALSE_POSITIVE` | `ACCEPTED_RISK`)*
- **Response 200 OK:**
  ```json
  {
    "success": true,
    "data": {
      "findingId": "find-018d5f32-74e1-7cb2-b43a-e9fa651f8b1e",
      "status": "FALSE_POSITIVE",
      "updatedAt": "2026-11-02T13:30:00.000Z",
      "updatedBy": "user-soc-analyst-02"
    }
  }
  ```

---

### 4.4 Export Scan Report (`GET /api/v1/scans/:scanId/report`)
Generates standardized executive and technical compliance report.
- **RBAC:** `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_VIEWER`, `AUDITOR`.
- **Query Parameters:** `format` (`JSON` | `HTML`).
- **Response 200 OK:** Returns structured report summary or rendered HTML artifact.
