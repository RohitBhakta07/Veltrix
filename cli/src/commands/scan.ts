import { Command } from 'commander';
import { ApiClient } from '../client/api-client.js';
import { ConfigManager } from '../config/config-manager.js';
import { OutputHandler } from '../formatters/output.js';
import { AuthenticationError, ScopePolicyError, CliError, ExitCode } from '../client/errors.js';
import type { ApiResponse } from '@veltrix/shared';

export function createScanCommand(configManager: ConfigManager): Command {
  const scanCmd = new Command('scan');
  scanCmd.description('Manage authorized security assessment scan jobs and scope verification');

  // Create / Initiate Scan
  scanCmd
    .command('create <siteId>')
    .description('Initiate a security assessment scan for an authorized website asset')
    .option('--scan-profile <type>', 'Scan assessment profile (PASSIVE, STANDARD_ACTIVE, FULL_AUDIT)', 'PASSIVE')
    .action(async (siteId, options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = options.json || globalOpts.json || resolved.outputFormat === 'json';
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
        // 1. Mandatory authoritative scan authorization check
        const authRes = await client.get<ApiResponse<{
          siteId: string;
          primaryDomain: string;
          status: string;
          scanBlocked: boolean;
          authorized: boolean;
          reason?: string;
          expiresAt?: string;
        }>>(`/websites/${siteId}/scan-authorization`);

        const auth = authRes.data;

        if (!auth.authorized || auth.scanBlocked) {
          throw new ScopePolicyError(
            `Target '${auth.primaryDomain}' (${siteId}) is NOT authorized for scanning: ${auth.reason || 'Domain verification required or asset in GRACE_PERIOD'}.`,
            'TARGET_UNAUTHORIZED',
            { siteId, domain: auth.primaryDomain, status: auth.status, scanBlocked: auth.scanBlocked }
          );
        }

        // 2. Query backend scan orchestrator
        const scanProfile = options.scanProfile || 'PASSIVE';
        try {
          const scanRes = await client.post<{ success: boolean; scan: { scanId: string; status: string; target: string } }>(
            '/scans',
            {
              siteId,
              profile: scanProfile,
            }
          );
          out.printSuccess(`Scan successfully launched for ${auth.primaryDomain}`, scanRes.scan);
        } catch (scanErr: unknown) {
          const isNotFound = (scanErr as CliError)?.code === 'NOT_FOUND' || (scanErr as Error)?.message?.includes('404');
          if (isNotFound) {
            // Report honestly: server endpoint POST /api/v1/scans is not yet deployed (TASK-808)
            out.handleError(
              new CliError(
                `Backend scan orchestrator endpoint 'POST /api/v1/scans' is not deployed on this server (Phase 8 TASK-808 in review). Target '${auth.primaryDomain}' (${siteId}) is confirmed authorized, but no background scan job could be created.`,
                ExitCode.GENERAL_ERROR,
                'BACKEND_CAPABILITY_UNAVAILABLE',
                {
                  siteId,
                  targetDomain: auth.primaryDomain,
                  scanAuthorized: true,
                  scanBlocked: false,
                  profile: scanProfile,
                  orchestratorStatus: 'TASK_808_PENDING_DEPLOYMENT',
                }
              )
            );
            return;
          }
          throw scanErr;
        }
      } catch (err) {
        out.handleError(err);
      }
    });

  // Scan Status
  scanCmd
    .command('status <scanId>')
    .description('Check operational status of an active or completed scan job')
    .action(async (scanId, options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = options.json || globalOpts.json || resolved.outputFormat === 'json';
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
        const res = await client.get<{ success: boolean; scan: Record<string, unknown> }>(`/scans/${scanId}`);
        out.printData(res.scan, { title: `Scan Status: ${scanId}` });
      } catch (err) {
        out.handleError(err);
      }
    });

  // Scan Cancel / Abort
  scanCmd
    .command('cancel <scanId>')
    .description('Trigger emergency abort for an in-progress scan job')
    .action(async (scanId, options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = options.json || globalOpts.json || resolved.outputFormat === 'json';
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
        const res = await client.post<{ success: boolean; message: string }>(`/scans/${scanId}/abort`, {});
        out.printSuccess(res.message || `Scan job '${scanId}' aborted successfully.`);
      } catch (err) {
        out.handleError(err);
      }
    });

  return scanCmd;
}
