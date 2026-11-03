/**
 * VELTRIX Active Security Rule: Open Redirect Canary (TASK-805)
 *
 * Dispatches canary redirect targets to detect unvalidated external redirection
 * via HTTP 3xx responses.
 *
 * Invariants:
 * - Operates with maxRedirects = 0; never follows outbound redirects.
 * - Inspects immediate 3xx response and Location header.
 * - Distinguishes unvalidated external redirects from relative or same-origin redirects.
 */

import crypto from 'node:crypto';
import type { CrawledPage } from '../../crawler/types.js';
import {
  type ActiveRuleInterface,
  type ActiveRuleExecutionContext,
  type ScannerFinding,
  RULE_ACTIVE_OPEN_REDIRECT,
} from '../../types.js';

export class OpenRedirectRule implements ActiveRuleInterface {
  public readonly id = RULE_ACTIVE_OPEN_REDIRECT;
  public readonly name = 'Active Open Redirect Canary Rule';
  public readonly description =
    'Supplies canary external URLs to parameter targets to detect unvalidated open redirection via 3xx response Location headers.';

  private static readonly REDIRECT_PARAM_CANDIDATES = [
    'redirect',
    'url',
    'next',
    'return',
    'returnUrl',
    'target',
    'dest',
    'destination',
    'r',
    'continue',
    'goto',
  ];

  public async evaluate(
    page: CrawledPage,
    context: ActiveRuleExecutionContext
  ): Promise<readonly ScannerFinding[]> {
    const findings: ScannerFinding[] = [];
    if (!page.url.startsWith('http://') && !page.url.startsWith('https://')) {
      return Object.freeze(findings);
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(page.url);
    } catch {
      return Object.freeze(findings);
    }

    // Identify candidate parameters
    const paramsToProbe: string[] = [];
    for (const key of parsedUrl.searchParams.keys()) {
      if (
        OpenRedirectRule.REDIRECT_PARAM_CANDIDATES.includes(key.toLowerCase()) &&
        !paramsToProbe.includes(key)
      ) {
        paramsToProbe.push(key);
      }
    }

    // If no explicit redirect parameter found in query, test top candidates
    if (paramsToProbe.length === 0) {
      paramsToProbe.push('redirect', 'next', 'returnUrl');
    }

    for (const param of paramsToProbe) {
      if (context.signal?.aborted) break;

      const canaryId = crypto.randomBytes(4).toString('hex');
      const targetHost = parsedUrl.hostname.toLowerCase();
      const canaryHost = targetHost === 'example.com' ? 'vltx-canary.invalid' : 'example.com';
      const canaryTarget = `https://${canaryHost}/vltx_canary_${canaryId}`;

      const probeUrlObj = new URL(page.url);
      probeUrlObj.searchParams.set(param, canaryTarget);
      const probeUrl = probeUrlObj.toString();

      try {
        const res = await context.dispatchProbe(probeUrl, { method: 'GET' });
        if (!res) continue;

        const status = res.status;
        const isRedirectStatus = [301, 302, 303, 307, 308].includes(status);
        if (!isRedirectStatus) {
          continue;
        }

        const locationHeader = res.headers['location'] || '';
        if (!locationHeader) {
          continue;
        }

        // Verify if Location targets the untrusted canary destination
        const isCanaryMatch =
          locationHeader.includes(canaryTarget) ||
          locationHeader.startsWith(`https://${canaryHost}`) ||
          locationHeader.startsWith(`http://${canaryHost}`) ||
          locationHeader.startsWith(`//${canaryHost}`);

        // Ensure location is not actually a relative or same-origin redirect
        let isSameOrigin = false;
        try {
          const locUrl = new URL(locationHeader, page.url);
          if (locUrl.hostname.toLowerCase() === parsedUrl.hostname.toLowerCase()) {
            isSameOrigin = true;
          }
        } catch {}

        if (isCanaryMatch && !isSameOrigin) {
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'OPEN_REDIRECT_UNVALIDATED',
              title: `Unvalidated Open Redirect via Parameter '${param}'`,
              severity: 'MEDIUM',
              confidence: 'CONFIRMED',
              description: `Parameter '${param}' on ${page.url} accepts untrusted external redirect targets and returned a ${status} redirect pointing to '${locationHeader}'.`,
              remediation:
                'Validate redirect targets against an explicit allowlist of authorized domains, or restrict redirection to relative paths (e.g. beginning with a single slash "/").',
              url: page.url,
              endpoint: probeUrl,
              evidence: Object.freeze({
                targetUrl: page.url,
                parameter: param,
                canaryTarget,
                redirectStatus: status,
                locationHeader,
              }),
            })
          );
          break; // Stop after first confirmed open redirect parameter on this page
        }
      } catch {
        // Probe errors fail safely without halting evaluation
      }
    }

    return Object.freeze(findings);
  }
}
