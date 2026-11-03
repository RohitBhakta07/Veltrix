/**
 * VELTRIX Active Security Rule: Path Traversal Canary (TASK-805)
 *
 * Submits harmless, non-sensitive traversal probe sequences to detect unhandled
 * file-system path normalization and inclusion flaws without accessing sensitive files.
 *
 * Invariants:
 * - Submits NON-EXISTENT canary paths: ../../../../etc/nonexistent_canary_probe.
 * - Strictly non-destructive. Never attempts file writes, deletion, or execution.
 * - Identifies characteristic unhandled file-system error signatures.
 * - Performs differential baseline check to avoid false positives.
 */

import type { CrawledPage } from '../../crawler/types.js';
import {
  type ActiveRuleInterface,
  type ActiveRuleExecutionContext,
  type ScannerFinding,
  RULE_ACTIVE_PATH_TRAVERSAL,
} from '../../types.js';

interface TraversalErrorPattern {
  readonly platform: string;
  readonly pattern: RegExp;
}

export class PathTraversalRule implements ActiveRuleInterface {
  public readonly id = RULE_ACTIVE_PATH_TRAVERSAL;
  public readonly name = 'Active Path Traversal Canary Rule';
  public readonly description =
    'Submits harmless non-existent traversal canaries to detect path normalization and file-inclusion vulnerabilities.';

  private static readonly CANARY_PATH_UNIX = '../../../../etc/nonexistent_canary_probe';
  private static readonly CANARY_PATH_WINDOWS = '..\\..\\..\\..\\windows\\nonexistent_canary_probe';

  private static readonly TRAVERSAL_PARAM_CANDIDATES = [
    'file',
    'path',
    'page',
    'doc',
    'folder',
    'include',
    'template',
    'view',
    'name',
    'item',
    'dir',
  ];

  private static readonly ERROR_PATTERNS: readonly TraversalErrorPattern[] = [
    {
      platform: 'Java',
      pattern: /(?:java\.io\.FileNotFoundException|java\.lang\.IllegalArgumentException.*path)/i,
    },
    {
      platform: 'PHP',
      pattern: /(?:open_basedir restriction in effect|Failed opening '.*' for inclusion|failed to open stream: No such file or directory)/i,
    },
    {
      platform: 'Node.js',
      pattern: /(?:ENOENT: no such file or directory|Cannot find module '.*nonexistent_canary_probe')/i,
    },
    {
      platform: '.NET',
      pattern: /(?:DirectoryNotFoundException|Illegal characters in path|Path\.GetFullPath)/i,
    },
    {
      platform: 'Generic Filesystem',
      pattern: /(?:No such file or directory.*nonexistent_canary_probe|Path traversal detected)/i,
    },
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

    const paramsToProbe: string[] = [];
    for (const key of parsedUrl.searchParams.keys()) {
      if (
        PathTraversalRule.TRAVERSAL_PARAM_CANDIDATES.includes(key.toLowerCase()) &&
        !paramsToProbe.includes(key)
      ) {
        paramsToProbe.push(key);
      }
    }

    if (paramsToProbe.length === 0) {
      paramsToProbe.push('file', 'path', 'page');
    }

    const probes = [PathTraversalRule.CANARY_PATH_UNIX, PathTraversalRule.CANARY_PATH_WINDOWS];

    for (const param of paramsToProbe) {
      if (context.signal?.aborted) break;

      for (const canaryPayload of probes) {
        if (context.signal?.aborted) break;

        const probeUrlObj = new URL(page.url);
        probeUrlObj.searchParams.set(param, canaryPayload);
        const probeUrl = probeUrlObj.toString();

        try {
          const res = await context.dispatchProbe(probeUrl, { method: 'GET' });
          if (!res) continue;

          const probeBody = res.text || '';
          const baselineBody = page.bodyText || '';

          let matchedPlatform: string | null = null;
          let matchedSnippet = '';

          for (const { platform, pattern } of PathTraversalRule.ERROR_PATTERNS) {
            const match = pattern.exec(probeBody);
            if (match) {
              // Differential check: Verify signature was not already present in baseline
              const baselineMatch = pattern.exec(baselineBody);
              if (!baselineMatch) {
                matchedPlatform = platform;
                const matchIdx = match.index;
                const snippetStart = Math.max(0, matchIdx - 30);
                const snippetEnd = Math.min(probeBody.length, matchIdx + match[0].length + 50);
                matchedSnippet = probeBody.slice(snippetStart, snippetEnd).trim();
                break;
              }
            }
          }

          if (matchedPlatform) {
            findings.push(
              Object.freeze({
                ruleId: this.id,
                vulnerabilityType: 'PATH_TRAVERSAL_ANOMALY',
                title: `Path Traversal Anomaly in Parameter '${param}' (${matchedPlatform})`,
                severity: 'HIGH',
                confidence: 'HIGH',
                description: `A benign non-existent traversal canary (${canaryPayload}) in parameter '${param}' triggered an unhandled file system error signature on ${page.url} (${matchedPlatform}).`,
                remediation:
                  'Normalize and validate file paths using a strict allowlist. Prohibit directory traversal sequences (../, ..\\) or use indirect file reference identifiers.',
                url: page.url,
                endpoint: probeUrl,
                evidence: Object.freeze({
                  targetUrl: page.url,
                  parameter: param,
                  canaryPayload,
                  detectedPlatform: matchedPlatform,
                  responseStatus: res.status,
                  responseBodySnippet: matchedSnippet.slice(0, 300),
                }),
              })
            );
            break; // Stop after first confirmed traversal finding for this parameter
          }
        } catch {
          // Probe errors fail safely without halting evaluation
        }
      }
    }

    return Object.freeze(findings);
  }
}
