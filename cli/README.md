# @veltrix/cli — VELTRIX Security Platform CLI

The production-ready command-line interface for the **VELTRIX** security scanning platform, SOC threat telemetry, and website attack monitoring system.

Designed for security engineers, SOC analysts, and DevSecOps pipelines.

---

## Key Architecture Principles

1. **Authoritative Backend Boundary**: All access control, authentication, tenant isolation, domain ownership verification, and scan permissions are authoritatively enforced by the VELTRIX backend API. The CLI acts as a secure client and never imports server storage or bypasses server policies.
2. **Client-Side Pre-Flight SSRF Guard**: The CLI prevents loopback, RFC 1918 private subnets, link-local addresses, cloud metadata endpoints (`169.254.169.254`), zone IDs, and prohibited administrative/database ports from ever being targeted or requested.
3. **Strict Credential Hygiene & Sanitization**: Configuration and session tokens stored in `~/.veltrix/config.json` are secured with `0600` permissions (read/write by owner only). All tokens, passwords, AWS keys, JWTs, and sensitive headers are scrubbed from terminal stdout/stderr, JSON output, and logs.
4. **Standardized Exit Codes**: Predictable process exit codes enable deterministic scripting and CI/CD pipeline integration.
5. **Dual Output Modes**: Formatted terminal tables with ANSI injection sanitization for human operators, and machine-readable `--json` output for automated tooling.

---

## Installation & Setup

### Prerequisites
- Node.js >= v20.0.0 (Node.js v22 LTS recommended)
- Access to a running VELTRIX backend instance (default: `http://localhost:4000/api/v1`)

### Local Development Setup
```bash
# In repository root
npm install
npm run build --workspace=@veltrix/cli

# Link binary globally
npm link --workspace=@veltrix/cli

# Verify installation
veltrix --version
veltrix --help
```

---

## Command Reference

### Global Options
All commands support the following global flags:
```text
  -u, --api-url <url>   Override target VELTRIX backend API URL
  -t, --token <token>   Authentication Bearer token or API key
  -o, --org <orgId>     Tenant organization context ID
  -p, --profile <name>  Active configuration profile name (default: "default")
  --json                Output machine-readable JSON
  -h, --help            Display help for command
  -V, --version         Output the version number
```

---

### 1. Platform Diagnostics (`veltrix doctor`)
Runs complete platform, network, environment, and security posture diagnostics.

```bash
# Run diagnostics table
veltrix doctor

# Structured diagnostic report
veltrix doctor --json
```

**Diagnostic Checks Evaluated:**
- **Node.js Runtime Environment**: Verifies runtime engine compatibility (`>= v20.0.0`).
- **Configuration & Secret Store**: Verifies `~/.veltrix/config.json` existence and file permissions (`0600`).
- **Backend API Connectivity**: Probes backend `/status` and `/health` endpoints and measures latency.
- **Analyst Authentication & RBAC Session**: Verifies active JWT token against `/api/v1/auth/me`.

---

### 2. Authentication Management (`veltrix auth`)

Manage analyst session credentials and tokens.

```bash
# Interactive login with masked terminal password entry (Recommended)
veltrix auth login

# Non-interactive login using environment variables (Secure CI / Automation)
export VELTRIX_EMAIL="ci_agent@corp.com"
export VELTRIX_PASSWORD="SecurePassword123!"
veltrix auth login

# Check active operator identity and RBAC role
veltrix auth status

# Rotate access token using refresh token (Token Family Rotation)
veltrix auth refresh

# Invalidate session token on server and purge local credentials
veltrix auth logout
```

---

### 3. Local Configuration Profiles (`veltrix config`)

Inspect and modify configuration settings and resolution precedence.

```bash
# View resolved configuration, profile, and source tracking
veltrix config show

# Update target backend API URL
veltrix config set apiUrl https://soc.veltrix.internal/api/v1

# Change default output format to JSON
veltrix config set outputFormat json

# Adjust network request timeout
veltrix config set timeoutMs 45000

# Validate local configuration file permissions
veltrix config validate
```

#### Precedence Hierarchy
Settings are resolved according to strict priority order:
1. **CLI Flags**: `--api-url`, `--token`, `--org`, `--json`, `--profile`
2. **Environment Variables**: `VELTRIX_API_URL`, `VELTRIX_TOKEN`, `VELTRIX_ORG_ID`, `VELTRIX_OUTPUT`, `VELTRIX_PROFILE`
3. **Config File Profile**: Settings in `~/.veltrix/config.json`
4. **Platform Defaults**: `http://localhost:4000/api/v1`, format: `table`, timeout: `30000ms`

---

### 4. Target Scope & Security Boundary (`veltrix target`)

Register, pre-validate, and manage authorized website assets.

```bash
# Pre-flight client SSRF check and server registration verification
veltrix target validate https://app.example.com

# List registered website assets and scan authorization status
veltrix target list
veltrix target list --status VERIFIED

# Register a new website asset for verification
veltrix target add example.com --name "Primary SaaS Portal" --env PRODUCTION

# Query authoritative server scan authorization receipt for a site
veltrix target check site_01a2b3c4d5

# Trigger server verification of DNS TXT ownership challenge
veltrix target verify site_01a2b3c4d5 --method DNS_TXT
```

#### Pre-flight Client SSRF Guard
The CLI strictly rejects any target that resolves to:
- Loopback addresses (`127.0.0.0/8`, `::1`, `localhost`)
- RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Cloud metadata services (`169.254.169.254`, AWS/GCP/Azure)
- Prohibited administrative & database ports (e.g. 22 SSH, 25 SMTP, 3306 MySQL, 5432 Postgres, 6379 Redis, 27017 MongoDB)
- URL embedded credentials (`https://user:pass@example.com`)
- Obfuscated decimal/hexadecimal IP representations (e.g. `2130706433`, `0x7f000001`)

---

### 5. Security Scans (`veltrix scan`)

Initiate and manage authorized security assessment scans.

```bash
# Launch a scan against an authorized site asset
veltrix scan create site_01a2b3c4d5 --scan-profile PASSIVE

# Check operational status of an active or historical scan
veltrix scan status scan_01a2b3c4d5

# Emergency abort for an in-progress scan job
veltrix scan cancel scan_01a2b3c4d5
```

> **Note on Task 808 Orchestrator**: Scan initiation checks the backend's authoritative `GET /websites/:siteId/scan-authorization` endpoint first. If the domain is unverified or blocked, the scan is rejected with `ScopePolicyError` (Exit code 6). If the domain is authorized but the backend scan orchestrator (`POST /api/v1/scans`, Phase 8 TASK-808) is not yet deployed, the CLI outputs `BACKEND_CAPABILITY_UNAVAILABLE` with exit code 1 to honestly inform operators and CI pipelines that worker execution is pending. Once TASK-808 is deployed on the backend, this command queues real background scan jobs.

---

### 6. Security Findings & Triage (`veltrix findings`)

Query and triage security findings and correlated threat detections.

```bash
# List open findings across targets
veltrix findings list

# Filter findings by severity and status
veltrix findings list --severity CRITICAL --status OPEN

# Filter by target website ID
veltrix findings list --site site_01a2b3c4d5 --limit 10

# Inspect detailed explainable evidence for an incident or detection
veltrix findings show inc_01a2b3c4d5
```

---

## Standard Exit Codes

| Code | Name | Meaning |
|---|---|---|
| `0` | `SUCCESS` | Operation completed successfully |
| `1` | `GENERAL_ERROR` | General runtime error, server error, or resource not found |
| `2` | `VALIDATION_ERROR` | Input parameter validation failed or malformed input |
| `3` | `AUTH_ERROR` | Authentication missing, invalid, or expired session token |
| `4` | `FORBIDDEN` | Authenticated analyst lacks RBAC permission for operation |
| `5` | `NETWORK_ERROR` | Backend connection refused, DNS resolution failed, or timeout |
| `6` | `SCOPE_ERROR` | Target scope violation or SSRF boundary violation |

---

## Automated Testing

```bash
# Run CLI test suite (Vitest)
npm test --workspace=@veltrix/cli

# Run type check
npm run typecheck --workspace=@veltrix/cli

# Build distribution
npm run build --workspace=@veltrix/cli

# Run entire monorepo suite
npm test
```

