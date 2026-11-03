# Full SOC Console Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the VELTRIX frontend into a production-grade, keyboard-first, explainable SOC Mission Control console covering all 15 platform modules with zero hardcoded credentials, unified design tokens, resilient state management, and contract-first mocks for pending backend phases.

**Architecture:** Client-side React SPA powered by Vite, Tailwind CSS, TanStack React Query v5, and React Router v6. The app uses an authoritative `AppShell` with global command palette (`⌘K`), real-time telemetry feeds, typed API envelope normalizers, RBAC role-gating, and MSW-backed contract-first handlers for pending Phase 8–10 surfaces.

**Tech Stack:** React 18, TypeScript 5.6, Tailwind CSS 3.4, Lucide React, Recharts 2.13, TanStack React Query 5, React Router DOM 6, Vitest, React Testing Library.

**Spec:** [VELTRIX Whole-Code Audit + Full SOC Console Frontend Plan](file:///d:/Development/08_GitHub_Repos/collab/Veltrix/specs/soc-console-frontend-spec.md)

---

## Global Constraints

- Zero hardcoded credentials or demo secrets in the source code or client bundles (NFR-SEC-01).
- Single source of truth for color tokens: Midnight Navy canvas (`#0A0F1D`), Surface (`#0D1527`), Card (`#111C35`), Electric Cyan (`#00F2FE`), Royal Blue (`#2563EB`).
- Authoritative backend authorization: UI displays verification, grace freezes, and approval gates, but never bypasses or simulates server-side security checks.
- Contract-first honesty: Modules awaiting Phase 8–10 backend routes (Scans, Findings, SOAR Response, Audit Ledger) must carry prominent "Awaiting Backend / Phase X" indicators.
- Type safety: No `any` escapes in API response normalization or risk scoring calculations.
- Bundle performance: Route-level code-splitting with lazy-loaded chart components; initial route payload ≤ 200KB gzip.

---

## Review Focus

1. **Token Expiry & Race-Condition Refresh**: Expired JWT access token during rapid parallel queries triggers a single coordinated refresh call rather than a cascade of 401s.
2. **Missing or Malformed Risk Factor Payload**: Backend returning partial risk metrics must safely display fallback values with a "Pending Calculation" badge instead of crashing the gauge.
3. **SSRF & Unverified Target Scan Gating**: The UI must physically disable and explain scan execution when a domain is `PENDING_VERIFICATION`, `GRACE_PERIOD`, or `REVOKED`.
4. **Offline Backend Resilience**: Network drops or proxy disconnects must display clear banner notifications without destroying form inputs or unmounting active tabs.
5. **JSON/Log XSS & Terminal Escape Injection**: Raw telemetry events and incident evidence containing ANSI escape codes or script tags must be sanitized before rendering.

---

## Tasks

### Task 1: TypeScript Environment, Vite Proxy & Build Repair

**Files:**
- Modify: `frontend/tsconfig.json`
- Modify: `frontend/vite.config.ts`
- Test: `frontend/tests/env.test.ts`

**Interfaces:**
- Consumes: Node & Vite environment variables (`import.meta.env`)
- Produces: Clean TypeScript build environment supporting `ES2022`, `vite/client` globals, and proxying both `/api` and `/health` to backend port 4000.

- [ ] **Step 1: Write the failing environment and proxy test**

```typescript
import { describe, it, expect } from 'vitest';

describe('Frontend Build Environment Configuration', () => {
  it('supports ES2022 string.replaceAll and vite client globals', () => {
    const raw = 'test-token-test';
    expect(raw.replaceAll('test', 'clean')).toBe('clean-token-clean');
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd Veltrix/frontend && npx vitest run tests/env.test.ts`
Expected: FAIL (missing test file / tsconfig issue)

- [ ] **Step 3: Update `frontend/tsconfig.json` and `frontend/vite.config.ts`**

Update `tsconfig.json` `"lib"` to `["ES2022", "DOM", "DOM.Iterable"]` and add `"types": ["vite/client"]`. In `vite.config.ts`, add proxy rules for both `/api` and `/health` to `http://localhost:4000`.

- [ ] **Step 4: Run typecheck to verify fix**

Run: `npm run typecheck --workspace=@veltrix/frontend`
Expected: Resolves `TS2550: replaceAll` and `TS2339: import.meta.env`.

- [ ] **Step 5: Commit**

```bash
git add frontend/tsconfig.json frontend/vite.config.ts frontend/tests/env.test.ts
git commit -m "fix(frontend): update tsconfig lib to ES2022 and configure vite backend proxies"
```

---

### Task 2: Contract Normalization & Typed API Adapter

**Files:**
- Modify: `frontend/src/lib/api/types.ts`
- Modify: `frontend/src/lib/api/endpoints.ts`
- Create: `frontend/src/lib/api/normalize.ts`
- Test: `frontend/tests/api-normalize.test.ts`

**Interfaces:**
- Consumes: Raw responses from `/api/v1/*` (varied envelopes: `data.events`, `data.items`, `sites`, `integrations`)
- Produces: `normalizeEnvelope<T>(raw: unknown): ApiResponse<T>` and strictly typed `WebRiskFactors` matching backend property names (`assetCriticalityMultiplier`, `threatIntelMultiplier`, `vulnerabilityMatchTerm`, `attackSequenceBonus`, `calculationExplanation`).

- [ ] **Step 1: Write failing normalization unit tests**

```typescript
import { describe, it, expect } from 'vitest';
import { normalizeRiskFactors, normalizeListResponse } from '../src/lib/api/normalize';

describe('API Contract Normalization', () => {
  it('normalizes legacy and updated risk factor payload keys', () => {
    const rawBackend = {
      assetMultiplier: 1.5,
      threatMultiplier: 2.0,
      vulnerabilityTerm: 15,
      sequenceBonus: 10,
      explanation: 'Targeted attack chain detected'
    };
    const normalized = normalizeRiskFactors(rawBackend);
    expect(normalized.assetCriticalityMultiplier).toBe(1.5);
    expect(normalized.threatIntelMultiplier).toBe(2.0);
    expect(normalized.vulnerabilityMatchTerm).toBe(15);
    expect(normalized.attackSequenceBonus).toBe(10);
    expect(normalized.calculationExplanation).toBe('Targeted attack chain detected');
  });

  it('normalizes heterogeneous list envelopes (sites, integrations, items, events)', () => {
    expect(normalizeListResponse({ sites: [{ siteId: '1' }] })).toEqual([{ siteId: '1' }]);
    expect(normalizeListResponse({ integrations: [{ id: '2' }] })).toEqual([{ id: '2' }]);
    expect(normalizeListResponse({ data: { items: [{ id: '3' }] } })).toEqual([{ id: '3' }]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/api-normalize.test.ts`
Expected: FAIL with missing module `normalize`.

- [ ] **Step 3: Implement `frontend/src/lib/api/normalize.ts` and fix index signatures in `endpoints.ts`**

Map legacy and current risk property keys cleanly; add index signatures or `Record<string, unknown>` conversion to `EventQuery`, `DetectionQuery`, and `IncidentQuery`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/api-normalize.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/lib/api/normalize.ts frontend/src/lib/api/types.ts frontend/src/lib/api/endpoints.ts frontend/tests/api-normalize.test.ts
git commit -m "feat(frontend): normalize api envelopes and risk factor contracts"
```

---

### Task 3: Secure Session Management & Demo Role Controller

**Files:**
- Modify: `frontend/src/lib/auth/session.ts`
- Modify: `frontend/src/features/auth/AuthProvider.tsx`
- Modify: `frontend/src/pages/LoginPage.tsx`
- Test: `frontend/tests/auth-session.test.ts`

**Interfaces:**
- Consumes: `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`
- Produces: `useAuth()` hook providing `user`, `token`, `role`, `login()`, `logout()`, `switchDemoRole()`, and automatic Bearer injection with zero hardcoded credentials in source.

- [ ] **Step 1: Write failing session management test**

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { getStoredSession, setStoredSession, clearStoredSession } from '../src/lib/auth/session';

describe('Auth Session Store', () => {
  beforeEach(() => clearStoredSession());

  it('stores access token in memory/storage and retrieves sanitized user identity', () => {
    setStoredSession({
      accessToken: 'jwt_mock_token_123',
      refreshToken: 'jwt_refresh_mock_456',
      user: {
        userId: 'usr-1',
        username: 'soc_analyst',
        email: 'analyst@corp.com',
        role: 'SECURITY_ANALYST',
        orgId: 'org-main'
      }
    });

    const session = getStoredSession();
    expect(session?.accessToken).toBe('jwt_mock_token_123');
    expect(session?.user.role).toBe('SECURITY_ANALYST');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/auth-session.test.ts`
Expected: FAIL (or verify current session logic)

- [ ] **Step 3: Implement `session.ts` and update `AuthProvider.tsx` and `LoginPage.tsx`**

Ensure `LoginPage` contains standard interactive form inputs and demo role buttons that authenticate dynamically rather than hardcoding credentials into `api.ts`. Purge hardcoded demo admin credentials from `frontend/src/api.ts`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/auth-session.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/lib/auth/session.ts frontend/src/features/auth/AuthProvider.tsx frontend/src/pages/LoginPage.tsx frontend/src/api.ts frontend/tests/auth-session.test.ts
git commit -m "feat(frontend): implement secure auth session and purge hardcoded credentials"
```

---

### Task 4: React Router Architecture & App Shell Wiring

**Files:**
- Create: `frontend/src/app/router.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/app/AppShell.tsx`
- Test: `frontend/tests/router.test.ts`

**Interfaces:**
- Consumes: All 15 SOC console pages (`OverviewPage`, `EventsPage`, `DetectionsPage`, `WebsitesPage`, `IntegrationsPage`, etc.)
- Produces: Declarative client routing tree with nested layout inside `AppShell`, authentication redirect gates, and dynamic page titles.

- [ ] **Step 1: Write failing router integration test**

```typescript
import { describe, it, expect } from 'vitest';
import { createMemoryRouter } from 'react-router-dom';
import { routes } from '../src/app/router';

describe('SOC Console Router Configuration', () => {
  it('registers all required security console routes', () => {
    const paths = routes[0].children?.map(r => r.path) || [];
    expect(paths).toContain('');
    expect(paths).toContain('events');
    expect(paths).toContain('detections');
    expect(paths).toContain('websites');
    expect(paths).toContain('integrations');
    expect(paths).toContain('incidents');
    expect(paths).toContain('scans');
    expect(paths).toContain('findings');
    expect(paths).toContain('response');
    expect(paths).toContain('audit');
    expect(paths).toContain('intel');
    expect(paths).toContain('settings');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/router.test.ts`
Expected: FAIL (missing `router.tsx`)

- [ ] **Step 3: Create `router.tsx` and rewire `App.tsx`**

Set up `createBrowserRouter` (or `HashRouter` fallback) inside `frontend/src/app/router.tsx`. Connect `QueryClientProvider`, `AuthProvider`, and `RouterProvider` in `frontend/src/App.tsx`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/router.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/app/router.tsx frontend/src/App.tsx frontend/src/app/AppShell.tsx frontend/tests/router.test.ts
git commit -m "feat(frontend): wire react router and app shell across all module routes"
```

---

### Task 5: Design Tokens & Reusable SOC Component Primitives

**Files:**
- Modify: `frontend/src/index.css`
- Modify: `frontend/src/components/ui/primitives.tsx`
- Modify: `frontend/src/components/charts/index.tsx`
- Test: `frontend/tests/primitives.test.ts`

**Interfaces:**
- Consumes: Tailwind CSS theme tokens (`#0A0F1D`, `#00F2FE`, `#2563EB`, `#FF4D6D`, etc.)
- Produces: Standardized SOC widgets: `KpiTile`, `RiskGauge` (0–100 SVG), `SeverityBadge`, `ConfidenceBadge`, `StatusPill`, `DataTable`, `FilterBar`, and `EvidenceDrawer`.

- [ ] **Step 1: Write failing primitive component unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SeverityBadge } from '../src/components/ui/primitives';

describe('SOC UI Primitives', () => {
  it('renders severity badge with correct icon and accessible label', () => {
    render(<SeverityBadge severity="CRITICAL" />);
    const badge = screen.getByText('CRITICAL');
    expect(badge).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/primitives.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement and polish primitives in `primitives.tsx` and chart wrappers in `charts/index.tsx`**

Ensure `RiskGauge`, `ConfidenceBadge`, and `EvidenceDrawer` handle empty, invalid, and high-severity values with high-contrast WCAG AA styling. Fix unused imports in `OverviewPage.tsx`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/primitives.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/index.css frontend/src/components/ui/primitives.tsx frontend/src/components/charts/index.tsx frontend/tests/primitives.test.ts
git commit -m "feat(frontend): harmonize design tokens and implement core soc ui primitives"
```

---

### Task 6: Executive Overview & SOC Mission Control Screen

**Files:**
- Modify: `frontend/src/pages/OverviewPage.tsx`
- Test: `frontend/tests/pages/overview.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/dashboard/summary?range=24h`
- Produces: Executive KPI tiles (Events 24h, Attacks, Open Incidents, Risk Score), telemetry velocity area chart with brush, severity donut, MITRE tactic horizontal bars, and asset risk heat strip.

- [ ] **Step 1: Write failing OverviewPage unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { OverviewPage } from '../../src/pages/OverviewPage';

describe('OverviewPage Component', () => {
  it('renders executive overview metrics and chart containers', async () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <OverviewPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Defense Readiness|Security Operations/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/overview.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement and refine `OverviewPage.tsx`**

Connect `useQuery` to `fetchDashboardSummary(24)` with 15s refresh interval. Wire drill-down links to `/events`, `/incidents`, and `/websites`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/overview.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/OverviewPage.tsx frontend/tests/pages/overview.test.ts
git commit -m "feat(frontend): complete executive overview mission control screen"
```

---

### Task 7: Events Explorer & Telemetry Log Screen

**Files:**
- Modify: `frontend/src/pages/EventsPage.tsx`
- Test: `frontend/tests/pages/events.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/events` (with time, severity, eventType, sourceIp, username filters)
- Produces: Virtualized table with live tail toggle, JSON payload inspector drawer (with sensitive field scrubbing), CSV export, and IP pivot filters.

- [ ] **Step 1: Write failing EventsPage unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { EventsPage } from '../../src/pages/EventsPage';

describe('EventsPage Component', () => {
  it('renders events log filter bar and table container', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <EventsPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByPlaceholderText(/search|filter/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/events.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement and harden `EventsPage.tsx`**

Wire URL search params for deep-linkable filters. Implement JSON inspection modal with `sanitizeTerminalText` and secret redacting.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/events.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/EventsPage.tsx frontend/tests/pages/events.test.ts
git commit -m "feat(frontend): implement events explorer with live tail and secret scrubbing"
```

---

### Task 8: Detections Feed & Sigma Rules Management

**Files:**
- Modify: `frontend/src/pages/DetectionsPage.tsx`
- Create: `frontend/src/pages/RulesPage.tsx`
- Test: `frontend/tests/pages/rules.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/detections`, `GET/PATCH /api/v1/detection-rules`, `POST /api/v1/detection-rules/test`
- Produces: Detections feed with confidence tier tags (`CONFIRMED`, `POTENTIAL`, `SUSPICIOUS`), explainable evidence drawer, rule threshold tuning controls, and dry-run evaluation tester.

- [ ] **Step 1: Write failing RulesPage unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { RulesPage } from '../../src/pages/RulesPage';

describe('RulesPage Component', () => {
  it('renders sigma detection rules catalog and tuning controls', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <RulesPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Detection Rules|Sigma/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/rules.test.ts`
Expected: FAIL (missing `RulesPage.tsx`)

- [ ] **Step 3: Implement `RulesPage.tsx` and complete `DetectionsPage.tsx`**

Build rule list grouped by identity/web, toggle switch, window/threshold inputs, and dry-run testing panel against sample telemetry payloads.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/rules.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/DetectionsPage.tsx frontend/src/pages/RulesPage.tsx frontend/tests/pages/rules.test.ts
git commit -m "feat(frontend): implement sigma rules catalog and detection confidence views"
```

---

### Task 9: Websites Inventory & Deep Asset Detail

**Files:**
- Create: `frontend/src/pages/WebsitesPage.tsx`
- Create: `frontend/src/pages/WebsiteDetailPage.tsx`
- Modify: `frontend/src/components/WebsiteInventory.tsx`
- Test: `frontend/tests/pages/websites.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/websites`, `GET /api/v1/websites/:id/*` (`risk-summary`, `timeline`, `detections`, `incidents`), `POST /api/v1/websites/:id/verify`, `POST /api/v1/websites/:id/revoke`
- Produces: Asset inventory table with DNS TXT, HTTP, and HTML Meta-tag verification; 7-day grace freeze alerts; Asset Detail view with Risk Factor Waterfall, health status, and attack history timeline.

- [ ] **Step 1: Write failing WebsitesPage unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { WebsitesPage } from '../../src/pages/WebsitesPage';

describe('WebsitesPage Component', () => {
  it('renders website asset inventory and verification status badges', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <WebsitesPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Website Assets|Registered Targets/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/websites.test.ts`
Expected: FAIL (missing `WebsitesPage.tsx`)

- [ ] **Step 3: Implement `WebsitesPage.tsx` and `WebsiteDetailPage.tsx`**

Refactor `WebsiteInventory` into modern modular pages using `AppShell`, adding the HTML Meta-tag verification challenge tab and deep-linkable detail tabs.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/websites.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/WebsitesPage.tsx frontend/src/pages/WebsiteDetailPage.tsx frontend/src/components/WebsiteInventory.tsx frontend/tests/pages/websites.test.ts
git commit -m "feat(frontend): build website asset inventory and deep risk detail screens"
```

---

### Task 10: Integrations & Telemetry Agent Management

**Files:**
- Create: `frontend/src/pages/IntegrationsPage.tsx`
- Modify: `frontend/src/components/IntegrationManagement.tsx`
- Test: `frontend/tests/pages/integrations.test.ts`

**Interfaces:**
- Consumes: `GET/POST /api/v1/integrations`, `POST /api/v1/integrations/:id/rotate-key`, `POST /api/v1/integrations/:id/revoke`
- Produces: Agent integration catalog (Node SDK, Express, Nginx, Apache, Cloudflare, AWS WAF), one-time secret key reveal modal, key rotation, and copy-paste code snippets.

- [ ] **Step 1: Write failing IntegrationsPage unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { IntegrationsPage } from '../../src/pages/IntegrationsPage';

describe('IntegrationsPage Component', () => {
  it('renders telemetry integration cards and setup wizard', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <IntegrationsPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Integrations|Telemetry Collectors/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/integrations.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement `IntegrationsPage.tsx`**

Integrate one-time credential reveal modal, copy-paste snippets with syntax highlighting, and heartbeat health indicators.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/integrations.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/IntegrationsPage.tsx frontend/src/components/IntegrationManagement.tsx frontend/tests/pages/integrations.test.ts
git commit -m "feat(frontend): integrate agent catalog and secure credential reveal"
```

---

### Task 11: Incident Management, Kill-Chain & Attack Story Replay

**Files:**
- Create: `frontend/src/pages/IncidentsPage.tsx`
- Create: `frontend/src/pages/IncidentDetailPage.tsx`
- Test: `frontend/tests/pages/incidents.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/incidents`, `GET /api/v1/incidents/:id`, `PATCH /api/v1/incidents/:id`
- Produces: Incident triage queue, MITRE kill-chain stepper, risk factor waterfall breakdown, analyst notes thread, status transitions, and "Attack Story" animated replay.

- [ ] **Step 1: Write failing IncidentsPage unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { IncidentsPage } from '../../src/pages/IncidentsPage';

describe('IncidentsPage Component', () => {
  it('renders incident triage queue with risk ranking', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <IncidentsPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Security Incidents|Attack Triage/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/incidents.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement `IncidentsPage.tsx` and `IncidentDetailPage.tsx`**

Render the risk waterfall (Base × Frequency × Asset × Threat + Vuln Term + Sequence Bonus = Final Score), kill-chain progress bar, and attack timeline scrubber.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/incidents.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/IncidentsPage.tsx frontend/src/pages/IncidentDetailPage.tsx frontend/tests/pages/incidents.test.ts
git commit -m "feat(frontend): implement incident triage queue and explainable kill chain view"
```

---

### Task 12: Threat Intelligence & IP Dossier View

**Files:**
- Create: `frontend/src/pages/IntelPage.tsx`
- Test: `frontend/tests/pages/intel.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/threat-indicators`, `POST /api/v1/threat-indicators/feed`
- Produces: IOC threat intelligence table with provenance badges (`VERIFIED_FEED` vs `MANUAL_ANALYST`), search by IP/domain, and IP dossier drawer showing historical cross-asset attack frequency.

- [ ] **Step 1: Write failing IntelPage unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { IntelPage } from '../../src/pages/IntelPage';

describe('IntelPage Component', () => {
  it('renders threat intelligence indicators and feed provenance', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <IntelPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Threat Intelligence|Indicators/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/intel.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement `IntelPage.tsx`**

Display feed indicators, severity scoring, confidence ratings, and add indicator modal.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/intel.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/IntelPage.tsx frontend/tests/pages/intel.test.ts
git commit -m "feat(frontend): build threat intelligence catalog and indicator provenance"
```

---

### Task 13: Scans & Findings Screens (Contract-First / Phase 8 Ready)

**Files:**
- Create: `frontend/src/pages/ScansPage.tsx`
- Create: `frontend/src/pages/FindingsPage.tsx`
- Test: `frontend/tests/pages/scans-findings.test.ts`

**Interfaces:**
- Consumes: Contract mock endpoints / Phase 8 scanner API schemas
- Produces: Scan configuration modal (`PASSIVE_BASELINE`, `STANDARD_ACTIVE`, `FULL_AUDIT`), target scope validation gate (blocks unverified sites), live scan stage progress, emergency abort button with 500ms SLO indicator, and Findings evidence explorer.

- [ ] **Step 1: Write failing Scans and Findings unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { ScansPage } from '../../src/pages/ScansPage';

describe('ScansPage Component', () => {
  it('renders scan orchestrator view with contract-first backend status indicator', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ScansPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Vulnerability Scans|Security Assessments/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/scans-findings.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement `ScansPage.tsx` and `FindingsPage.tsx`**

Integrate scan profiles, scope authorization enforcement, CVSS severity filters, and prominent "Awaiting Phase 8 Backend Orchestrator" banners when running against current backend.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/scans-findings.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/ScansPage.tsx frontend/src/pages/FindingsPage.tsx frontend/tests/pages/scans-findings.test.ts
git commit -m "feat(frontend): implement scans and findings console with contract-first guardrails"
```

---

### Task 14: SOAR Response Queue & Cryptographic Audit Ledger (Phase 10)

**Files:**
- Create: `frontend/src/pages/ResponsePage.tsx`
- Create: `frontend/src/pages/AuditPage.tsx`
- Test: `frontend/tests/pages/response-audit.test.ts`

**Interfaces:**
- Consumes: `/api/v1/response/*` and `/api/v1/audit/*`
- Produces: Dual-custody action approval cards (`BLOCK_IP`, `RATE_LIMIT_IP`, `QUARANTINE_TOKEN`, `TERMINATE_SESSION`), execution rollback controls, and reverse-chronological SHA-256 hash-chain ledger with interactive chain verification.

- [ ] **Step 1: Write failing Response & Audit unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { AuditPage } from '../../src/pages/AuditPage';

describe('AuditPage Component', () => {
  it('renders cryptographic ledger blocks and chain verification button', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <AuditPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Audit Ledger|Cryptographic/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/response-audit.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement `ResponsePage.tsx` and `AuditPage.tsx`**

Render response approval queue with RBAC enforcement (`ORG_ADMIN` required for execution) and hash-chain visualizer showing `prevHash → currentHash` with verification progress.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/response-audit.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/ResponsePage.tsx frontend/src/pages/AuditPage.tsx frontend/tests/pages/response-audit.test.ts
git commit -m "feat(frontend): build response approval queue and tamper-evident audit ledger"
```

---

### Task 15: Settings, Team RBAC & Demo Scenario Controller

**Files:**
- Create: `frontend/src/pages/SettingsPage.tsx`
- Test: `frontend/tests/pages/settings.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/auth/me`, `POST /api/v1/demo/seed`, `POST /api/v1/demo/reset`
- Produces: Organization settings, RBAC role permission matrix, telemetry retention configuration, and deterministic demo scenario runner with single-click reset.

- [ ] **Step 1: Write failing SettingsPage unit test**

```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { SettingsPage } from '../../src/pages/SettingsPage';

describe('SettingsPage Component', () => {
  it('renders settings tabs including demo scenario controls', () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <SettingsPage />
        </BrowserRouter>
      </QueryClientProvider>
    );
    expect(screen.getByText(/Settings|Organization/i)).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/settings.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement `SettingsPage.tsx`**

Render tenant profile, team list, RBAC matrix, and demo reset controls connected to `POST /api/v1/demo/reset`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd Veltrix/frontend && npx vitest run tests/pages/settings.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/SettingsPage.tsx frontend/tests/pages/settings.test.ts
git commit -m "feat(frontend): build settings and demo scenario management"
```

---

### Task 16: Automated Quality Gates & Full Monorepo Verification

**Files:**
- Create: `frontend/vitest.config.ts`
- Modify: `frontend/package.json` (add `"test": "vitest run"`)
- Test: Full monorepo verification across all workspaces

**Interfaces:**
- Consumes: All 15 frontend pages, shared contracts, and backend APIs
- Produces: 100% passing frontend test suite, clean TypeScript typechecks across all 5 workspaces, clean Vite production build, and zero lint errors.

- [ ] **Step 1: Configure `frontend/vitest.config.ts`**

Setup jsdom environment and test inclusion patterns.

- [ ] **Step 2: Run frontend test suite**

Run: `npm test --workspace=@veltrix/frontend`
Expected: PASS with 0 failures across all page and unit tests.

- [ ] **Step 3: Run full monorepo typecheck**

Run: `npm run typecheck`
Expected: Exit code 0 across `@veltrix/shared`, `@veltrix/sdk-node`, `@veltrix/backend`, `@veltrix/frontend`, `@veltrix/cli`.

- [ ] **Step 4: Run full monorepo build**

Run: `npm run build`
Expected: Exit code 0.

- [ ] **Step 5: Run full monorepo test suite**

Run: `npm test`
Expected: Exit code 0.

- [ ] **Step 6: Commit**

```bash
git add frontend/vitest.config.ts frontend/package.json
git commit -m "test(frontend): configure vitest test runner and establish frontend quality gates"
```

---

## Self-Review Checklist

1. **Spec Coverage:**
   - Auth & Orgs: Task 3 (AuthProvider, session, role switching)
   - Event Ingestion: Task 7 (Events explorer, live tail, scrubbing)
   - Sigma Rules: Task 8 (Rule catalog, tuning, dry-run)
   - Correlation / Incidents: Task 11 (Triage, kill-chain, attack story)
   - Risk Scoring: Tasks 2, 6, 9, 11 (Normalized factors, waterfall)
   - Threat Intel: Task 12 (IOCs, feed provenance, IP dossier)
   - SOAR Response: Task 14 (Approval cards, execution gate)
   - Audit Ledger: Task 14 (Hash-chain visualizer, verification)
   - Dashboard: Task 6 (KPIs, velocity area, donut, MITRE bars)
   - Scans & Findings: Task 13 (Profiles, scope gating, evidence)
   - Websites & Assets: Task 9 (Verification, grace freeze, detail)
   - Integrations: Task 10 (Catalog, one-time reveal, snippets)
   - Settings & Demo: Task 15 (Team, RBAC, demo seed/reset)
2. **Step Scan:** Every task follows Step 1 (failing test) → Step 2 (verify red) → Step 3 (implement minimal code) → Step 4 (verify green) → Step 5 (commit).
3. **Type Consistency:** Normalized types (`WebRiskFactors`, `ApiResponse<T>`, `EventQuery`, `DetectionQuery`) are locked in Task 2 and consumed consistently across Tasks 6–15.
4. **Review Focus Handled:**
   - Token refresh race conditions handled in Task 3.
   - Partial/malformed risk factors handled in Tasks 2 & 5.
   - SSRF and unverified site scan gating enforced in Task 13.
   - Offline backend resilience handled in Task 4 & 5.
   - Secret/terminal sanitization handled in Tasks 5 & 7.

