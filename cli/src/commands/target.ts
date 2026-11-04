import { Command } from 'commander';
import { ApiClient } from '../client/api-client.js';
import { ConfigManager } from '../config/config-manager.js';
import { OutputHandler } from '../formatters/output.js';
import { validateTarget } from '../security/target-validator.js';
import { ValidationError, AuthenticationError } from '../client/errors.js';
import type { ApiResponse, WebsiteAsset } from '@veltrix/shared';

export function createTargetCommand(configManager: ConfigManager): Command {
  const targetCmd = new Command('target');
  targetCmd.description('Register, validate, and manage authorized website scan targets');

  // Validate Target (Client SSRF guard + optional backend verification)
  targetCmd
    .command('validate <target>')
    .description('Validate a target URL or domain against SSRF boundaries and server authorization')
    .action(async (target, _options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const out = new OutputHandler(resolved.outputFormat === 'json');

      // 1. Client-side security and SSRF pre-flight validation
      const preflight = validateTarget(target);
      if (!preflight.valid) {
        out.handleError(
          new ValidationError(
            `Target validation rejected: ${preflight.error}`,
            preflight.errorCode || 'PROHIBITED_DESTINATION'
          )
        );
        return;
      }

      let serverStatus = 'Not Checked (No active authentication token)';
      let serverAsset: WebsiteAsset | undefined = undefined;

      // 2. Authoritative server check if authenticated
      if (resolved.token) {
        try {
          const client = new ApiClient({
            baseUrl: resolved.apiUrl,
            token: resolved.token,
            orgId: resolved.orgId,
            timeoutMs: resolved.timeoutMs,
          });

          const sitesRes = await client.get<ApiResponse<WebsiteAsset[]> & { sites: WebsiteAsset[] }>('/websites', {
            limit: 100,
          });

          const allSites = sitesRes.sites || sitesRes.data || [];
          const matched = allSites.find(
            (s) => s.primaryDomain.toLowerCase() === preflight.domain.toLowerCase()
          );

          if (matched) {
            serverAsset = matched;
            serverStatus = matched.status === 'VERIFIED'
              ? (matched.scanBlocked ? 'VERIFIED (Scanning Blocked)' : 'VERIFIED (Authorized for Scanning)')
              : `UNVERIFIED (${matched.status} - Scanning Forbidden)`;
          } else {
            serverStatus = 'UNREGISTERED (Must be added via target add and verified before scanning)';
          }
        } catch {
          serverStatus = 'Backend check skipped due to connection or authentication issue.';
        }
      }

      const result = {
        inputTarget: target,
        normalizedUrl: preflight.normalizedUrl,
        domain: preflight.domain,
        port: preflight.port || (preflight.protocol === 'https:' ? 443 : 80),
        protocol: preflight.protocol,
        clientPreflight: 'PASSED (Zero SSRF / Prohibited Subnet Violations)',
        serverAuthorizationStatus: serverStatus,
        registeredSiteId: serverAsset?.siteId || null,
        scanBlocked: serverAsset ? serverAsset.scanBlocked : true,
      };

      out.printSuccess('Target validation completed.', result);
    });

  // List Targets
  targetCmd
    .command('list')
    .description('List registered website targets and their scan readiness status')
    .option('--status <status>', 'Filter by status (VERIFIED, PENDING_VERIFICATION, GRACE_PERIOD, EXPIRED)')
    .action(async (options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      if (!resolved.token) {
        out.handleError(
          new AuthenticationError("Authentication required. Run 'veltrix auth login' first.")
        );
        return;
      }

      const client = new ApiClient({
        baseUrl: resolved.apiUrl,
        token: resolved.token,
        orgId: resolved.orgId,
        timeoutMs: resolved.timeoutMs,
      });

      try {
        const res = await client.get<{ success: boolean; sites?: WebsiteAsset[]; data?: WebsiteAsset[]; total?: number }>('/websites', {
          status: options.status,
          limit: 100,
        });

        const sites = res.sites || res.data || [];

        if (isJson) {
          out.printJson({
            success: true,
            data: {
              items: sites,
              total: sites.length,
            },
          });
          return;
        }

        out.printData(sites, {
          title: 'Registered Website Scan Targets',
          table: {
            rows: sites,
            columns: [
              { header: 'Site ID', key: 'siteId', width: 22 },
              { header: 'Primary Domain', key: 'primaryDomain', width: 25 },
              { header: 'Environment', key: 'environment', width: 14 },
              { header: 'Status', key: 'status', width: 22 },
              {
                header: 'Scan Allowed',
                format: (s) => (s.scanBlocked ? 'NO (Blocked)' : 'YES (Authorized)'),
                width: 18,
              },
              { header: 'Risk Tier', key: 'riskTier', width: 12 },
            ],
          },
        });
      } catch (err) {
        out.handleError(err);
      }
    });

  // Add Target
  targetCmd
    .command('add <domain>')
    .description('Register a new website asset for verification and authorized scanning')
    .option('--name <name>', 'Descriptive asset name')
    .option('--env <environment>', 'Deployment environment (PRODUCTION, STAGING, DEVELOPMENT)', 'PRODUCTION')
    .option('--risk <riskTier>', 'Risk tier (CRITICAL, HIGH, MEDIUM, LOW)', 'MEDIUM')
    .option('--subdomains <subdomains...>', 'Approved subdomain list')
    .action(async (domain, options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      // Pre-flight target validation
      const preflight = validateTarget(domain);
      if (!preflight.valid) {
        out.handleError(new ValidationError(`Target rejected: ${preflight.error}`));
        return;
      }

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
        const name = options.name || preflight.domain;
        const res = await client.post<{ success: boolean; site?: WebsiteAsset; data?: WebsiteAsset }>('/websites', {
          name,
          primaryDomain: preflight.domain,
          approvedSubdomains: options.subdomains || [],
          environment: options.env.toUpperCase(),
          riskTier: options.risk.toUpperCase(),
        });

        const site = res.site || res.data!;
        out.printSuccess(`Website target registered: ${site.primaryDomain} (${site.siteId})`, {
          'Site ID': site.siteId,
          'Primary Domain': site.primaryDomain,
          'Status': site.status,
          'Scan Blocked': site.scanBlocked ? 'YES (Verification Required)' : 'NO',
          'Verification Token': site.verificationToken,
          'DNS TXT Host': site.dnsTxtRecord?.host || `_veltrix-challenge.${site.primaryDomain}`,
          'DNS TXT Value': site.dnsTxtRecord?.value || site.verificationToken,
          'HTTP Challenge URL': site.httpChallenge?.url || `/.well-known/veltrix-challenge/${site.verificationToken}`,
        });
      } catch (err) {
        out.handleError(err);
      }
    });

  // Check Target Scan Authorization
  targetCmd
    .command('check <siteId>')
    .description('Check authoritative server scan authorization for a website asset')
    .action(async (siteId, _options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = resolved.outputFormat === 'json';
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
        const res = await client.get<ApiResponse<{
          siteId: string;
          primaryDomain: string;
          status: string;
          scanBlocked: boolean;
          authorized: boolean;
          reason?: string;
          expiresAt?: string;
        }>>(`/websites/${siteId}/scan-authorization`);

        const authData = res.data;

        if (isJson) {
          out.printJson({
            success: true,
            data: authData,
          });
          return;
        }

        out.printData(authData, {
          title: `Scan Scope Authorization: ${authData.primaryDomain}`,
          summary: {
            'Site ID': authData.siteId,
            'Primary Domain': authData.primaryDomain,
            'Ownership Status': authData.status,
            'Scan Authorized': authData.authorized ? 'AUTHORIZED' : 'DENIED / FROZEN',
            'Scan Blocked': authData.scanBlocked ? 'YES' : 'NO',
            'Policy Reason': authData.reason || 'Asset is verified and within authorized validity period.',
            'Authorization Expiry': authData.expiresAt || 'N/A',
          },
        });
      } catch (err) {
        out.handleError(err);
      }
    });

  // Verify Target Domain Ownership Challenge
  targetCmd
    .command('verify <siteId>')
    .description('Trigger server verification of DNS TXT, HTTP Challenge, or Meta Tag')
    .option('--method <method>', 'Verification method: DNS_TXT | HTTP_CHALLENGE | HTML_META', 'DNS_TXT')
    .action(async (siteId, options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = resolved.outputFormat === 'json';
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
        const verifyRes = await client.post<{
          success: boolean;
          verified: boolean;
          status: string;
          site?: WebsiteAsset;
          message?: string;
        }>(`/websites/${siteId}/verify`, {
          method: options.method.toUpperCase(),
        });

        if (verifyRes.verified) {
          out.printSuccess(`Domain ownership verified successfully! Target is now unlocked for security scans.`, {
            siteId,
            status: verifyRes.status || 'VERIFIED',
            scanAllowed: 'YES',
          });
        } else {
          out.handleError(
            new ValidationError(
              `Verification challenge failed: ${verifyRes.message || 'DNS TXT or challenge token not detected yet.'}`
            )
          );
        }
      } catch (err) {
        out.handleError(err);
      }
    });

  return targetCmd;
}
