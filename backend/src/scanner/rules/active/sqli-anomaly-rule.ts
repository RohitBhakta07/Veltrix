/**
 * VELTRIX Active Security Rule: SQL Syntax Anomaly Assessment (TASK-805)
 *
 * Appends benign syntax disruptor tokens (', ", '') to numeric or string query
 * parameters to identify unhandled SQL syntax error signatures.
 *
 * Invariants:
 * - Strictly non-destructive. NEVER issues SQL DROP, DELETE, UPDATE, or INSERT.
 * - Does NOT perform data exfiltration, blind sleep loops (SLEEP/BENCHMARK), or boolean injection.
 * - Compares baseline response vs probe response to suppress pre-existing application errors.
 * - Searches response body for deterministic RDBMS syntax error signatures.
 */

import type { CrawledPage } from '../../crawler/types.js';
import {
  type ActiveRuleInterface,
  type ActiveRuleExecutionContext,
  type ScannerFinding,
  RULE_ACTIVE_SQLI_ANOMALY,
} from '../../types.js';

interface SqlErrorPattern {
  readonly rdbms: string;
  readonly pattern: RegExp;
}

export class SqliAnomalyRule implements ActiveRuleInterface {
  public readonly id = RULE_ACTIVE_SQLI_ANOMALY;
  public readonly name = 'Active SQL Syntax Anomaly Rule';
  public readonly description =
    'Sends benign quote disruptors to detect unhandled SQL syntax error signatures without executing data modification or extraction.';

  // Known RDBMS syntax error patterns across MySQL, PostgreSQL, Oracle, SQLite, MSSQL/ODBC
  private static readonly SQL_ERROR_PATTERNS: readonly SqlErrorPattern[] = [
    {
      rdbms: 'MySQL / MariaDB',
      pattern: /(?:you have an error in your sql syntax|check the manual that corresponds to your (?:mysql|mariadb) server version|MySqlException|mysqli_query)/i,
    },
    {
      rdbms: 'PostgreSQL',
      pattern: /(?:syntax error at or near|PostgreSQL query failed|PSQLException|org\.postgresql\.util\.PSQLException)/i,
    },
    {
      rdbms: 'Microsoft SQL Server / Access',
      pattern: /(?:ODBC Microsoft Access Driver|Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|SqlException|Driver.*SQL[\-_ ]*Server)/i,
    },
    {
      rdbms: 'Oracle',
      pattern: /(?:ORA-00933|ORA-00936|ORA-01756|Oracle error|OracleException)/i,
    },
    {
      rdbms: 'SQLite',
      pattern: /(?:near ".*": syntax error|unrecognized token:|SQLite3::SQLException|sqlite3\.OperationalError)/i,
    },
    {
      rdbms: 'Generic SQL Error',
      pattern: /(?:quoted string not properly terminated|unclosed mark after the character string)/i,
    },
  ];

  // Benign syntax disruptor tokens
  private static readonly DISRUPTORS = ["'", '"', "''"];

  private static readonly DEFAULT_PROBE_PARAMS = ['id', 'user', 'cat', 'item', 'page', 'category'];

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
      if (!paramsToProbe.includes(key)) {
        paramsToProbe.push(key);
      }
    }

    if (paramsToProbe.length === 0) {
      paramsToProbe.push(...SqliAnomalyRule.DEFAULT_PROBE_PARAMS);
    }

    for (const param of paramsToProbe) {
      if (context.signal?.aborted) break;

      const baseVal = parsedUrl.searchParams.get(param) || '1';

      for (const disruptor of SqliAnomalyRule.DISRUPTORS) {
        if (context.signal?.aborted) break;

        const probeUrlObj = new URL(page.url);
        probeUrlObj.searchParams.set(param, `${baseVal}${disruptor}`);
        const probeUrl = probeUrlObj.toString();

        try {
          const res = await context.dispatchProbe(probeUrl, { method: 'GET' });
          if (!res) continue;

          const probeBody = res.text || '';
          const baselineBody = page.bodyText || '';

          // 1. Check for explicit RDBMS error signatures
          let matchedRdbms: string | null = null;
          let matchedSnippet = '';

          for (const { rdbms, pattern } of SqliAnomalyRule.SQL_ERROR_PATTERNS) {
            const probeMatch = pattern.exec(probeBody);
            if (probeMatch) {
              // Differential check: Verify error was NOT already present in baseline
              const baselineMatch = pattern.exec(baselineBody);
              if (!baselineMatch) {
                matchedRdbms = rdbms;
                const matchIdx = probeMatch.index;
                const snippetStart = Math.max(0, matchIdx - 30);
                const snippetEnd = Math.min(probeBody.length, matchIdx + probeMatch[0].length + 50);
                matchedSnippet = probeBody.slice(snippetStart, snippetEnd).trim();
                break;
              }
            }
          }

          if (matchedRdbms) {
            findings.push(
              Object.freeze({
                ruleId: this.id,
                vulnerabilityType: 'SQL_INJECTION_SYNTAX_ANOMALY',
                title: `SQL Syntax Anomaly in Parameter '${param}' (${matchedRdbms})`,
                severity: 'HIGH',
                confidence: 'HIGH',
                description: `A benign syntax disruptor token (${disruptor}) injected into parameter '${param}' on ${page.url} triggered an explicit ${matchedRdbms} database error signature.`,
                remediation:
                  'Use parameterized prepared statements (parameter binding) or an Object-Relational Mapper (ORM) for all database queries. Disable verbose database error display.',
                url: page.url,
                endpoint: probeUrl,
                evidence: Object.freeze({
                  targetUrl: page.url,
                  parameter: param,
                  disruptorPayload: disruptor,
                  rdbms: matchedRdbms,
                  responseStatus: res.status,
                  responseBodySnippet: matchedSnippet.slice(0, 300),
                }),
              })
            );
            break; // Stop probing further disruptors on this parameter once confirmed
          } else if (res.status === 500 && page.status !== 500) {
            // 2. Status code anomaly: 200 -> 500 without explicit signature (heuristic LOW confidence)
            findings.push(
              Object.freeze({
                ruleId: this.id,
                vulnerabilityType: 'SQL_INJECTION_SYNTAX_ANOMALY',
                title: `Potential SQL Syntax Anomaly (HTTP 500) in Parameter '${param}'`,
                severity: 'MEDIUM',
                confidence: 'LOW',
                description: `A benign syntax disruptor token (${disruptor}) in parameter '${param}' caused the server to return HTTP 500 (baseline was ${page.status}). No explicit SQL error text was disclosed.`,
                remediation:
                  'Audit parameter handling in server-side query construction and ensure parameterized queries are used.',
                url: page.url,
                endpoint: probeUrl,
                evidence: Object.freeze({
                  targetUrl: page.url,
                  parameter: param,
                  disruptorPayload: disruptor,
                  responseStatus: 500,
                  baselineStatus: page.status,
                }),
              })
            );
            break;
          }
        } catch {
          // Probe errors fail safely without halting evaluation
        }
      }
    }

    return Object.freeze(findings);
  }
}
