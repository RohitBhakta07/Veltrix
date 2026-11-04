import { Command } from 'commander';
import { ApiClient } from '../client/api-client.js';
import { ConfigManager } from '../config/config-manager.js';
import { OutputHandler } from '../formatters/output.js';
import { AuthenticationError, CliError } from '../client/errors.js';
import type { ApiResponse, Incident, Detection } from '@veltrix/shared';

export function createFindingsCommand(configManager: ConfigManager): Command {
  const findingsCmd = new Command('findings');
  findingsCmd.description('Inspect, filter, and triage security findings and threat detections');

  // List findings
  findingsCmd
    .command('list')
    .description('List security findings and incidents correlated across scan targets')
    .option('-s, --severity <severity>', 'Filter by severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)')
    .option('--status <status>', 'Filter by incident status (OPEN, IN_TRIAGE, INVESTIGATING, CONTAINED, CLOSED)')
    .option('--site <siteId>', 'Filter by target website ID')
    .option('-l, --limit <limit>', 'Maximum findings to display', '20')
    .action(async (options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = options.json || resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      if (!resolved.token) {
        out.handleError(new AuthenticationError("Authentication required. Run 'veltrix auth login' first."));
        return;
      }

      const client = new ApiClient({
        baseUrl: resolved.apiUrl,
        token: resolved.token,
        orgId: resolved.orgId,
        timeoutMs: resolved.timeoutMs,
      });

      const limit = parseInt(options.limit, 10) || 20;

      try {
        const res = await client.get<ApiResponse<{
          items: Incident[];
          total: number;
        }>>('/incidents', {
          status: options.status,
          siteId: options.site,
          limit,
        });

        let items = res.data?.items || [];

        // Apply client-side severity filtering if requested
        if (options.severity) {
          const targetSev = String(options.severity).toUpperCase();
          items = items.filter((item) => item.severity?.toUpperCase() === targetSev);
        }

        if (isJson) {
          out.printJson({
            success: true,
            data: {
              items,
              total: items.length,
            },
          });
          return;
        }

        if (items.length === 0) {
          out.printInfo('No security findings or incidents found matching specified criteria.');
          return;
        }

        const tableRows = items.map((inc) => ({
          'ID': inc.incidentId,
          'Severity': inc.severity || 'UNKNOWN',
          'Title': inc.title,
          'Status': inc.status,
          'Target / Site': (inc as any).siteId || (inc as any).affectedTarget || '-',
          'Detected At': inc.createdAt ? new Date(inc.createdAt).toLocaleString() : '-',
        }));

        out.printTable(tableRows, {
          title: `Security Findings & Incidents (${items.length} total)`,
        });
      } catch (err) {
        out.handleError(err);
      }
    });

  // Show individual finding
  findingsCmd
    .command('show <findingId>')
    .description('Display detailed breakdown and explainable evidence for a finding')
    .action(async (findingId, options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = options.json || resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      if (!resolved.token) {
        out.handleError(new AuthenticationError("Authentication required. Run 'veltrix auth login' first."));
        return;
      }

      const client = new ApiClient({
        baseUrl: resolved.apiUrl,
        token: resolved.token,
        orgId: resolved.orgId,
        timeoutMs: resolved.timeoutMs,
      });

      try {
        // Try incident endpoint first
        try {
          const incidentRes = await client.get<ApiResponse<Incident>>(`/incidents/${findingId}`);
          const inc = incidentRes.data;

          if (isJson) {
            out.printJson({ success: true, data: inc });
            return;
          }

          out.printData(inc, {
            title: `Security Finding Detail: ${inc.incidentId}`,
            summary: {
              'Finding ID': inc.incidentId,
              'Title': inc.title,
              'Severity': inc.severity,
              'Status': inc.status,
              'Risk Score': (inc as any).riskScore !== undefined ? `${(inc as any).riskScore} / 100` : '-',
              'Target / Site ID': (inc as any).siteId || (inc as any).affectedTarget || '-',
              'Created At': inc.createdAt ? new Date(inc.createdAt).toISOString() : '-',
              'Summary': (inc as any).summary || inc.title,
            },
          });
          return;
        } catch (incidentErr) {
          // If not found in incidents, try detections endpoint
          if (incidentErr instanceof CliError && (incidentErr.code === 'NOT_FOUND' || (incidentErr as any).statusCode === 404)) {
            const detRes = await client.get<ApiResponse<Detection>>(`/detections/${findingId}`);
            const det = detRes.data;

            if (isJson) {
              out.printJson({ success: true, data: det });
              return;
            }

            out.printData(det, {
              title: `Threat Detection Detail: ${det.detectionId}`,
              summary: {
                'Detection ID': det.detectionId,
                'Rule ID': det.ruleId,
                'Rule Name': det.ruleName,
                'Severity': det.severity,
                'Confidence': `${Math.round(det.confidence * 100)}%`,
                'Detected At': new Date(det.detectedAt).toISOString(),
                'Target': (det.evidence?.details as any)?.target || '-',
              },
            });
            return;
          }

          throw incidentErr;
        }
      } catch (err) {
        out.handleError(err);
      }
    });

  return findingsCmd;
}
