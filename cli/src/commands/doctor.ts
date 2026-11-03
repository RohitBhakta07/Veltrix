import fs from 'node:fs';
import { Command } from 'commander';
import { ApiClient } from '../client/api-client.js';
import { ConfigManager } from '../config/config-manager.js';
import { OutputHandler } from '../formatters/output.js';
import type { ApiResponse, AuthUser } from '@veltrix/shared';

export interface DiagnosticCheckResult {
  name: string;
  pass: boolean;
  status: 'PASS' | 'WARN' | 'FAIL';
  detail: string;
  remediation?: string;
}

export function createDoctorCommand(configManager: ConfigManager): Command {
  const doctorCmd = new Command('doctor');
  doctorCmd.description('Run comprehensive platform, network, environment, and security diagnostics');

  doctorCmd.action(async (options, cmd) => {
    const globalOpts = cmd.optsWithGlobals();
    const resolved = configManager.resolveConfig(globalOpts);
    const isJson = options.json || resolved.outputFormat === 'json';
    const out = new OutputHandler(isJson);

    const checks: Record<string, DiagnosticCheckResult> = {};

    // 1. Node.js Runtime Check
    const nodeMajor = parseInt(process.versions.node.split('.')[0] || '0', 10);
    const nodePass = nodeMajor >= 20;
    checks.nodeRuntime = {
      name: 'Node.js Runtime Environment',
      pass: nodePass,
      status: nodePass ? 'PASS' : 'WARN',
      detail: `v${process.versions.node} (${process.platform}-${process.arch})`,
      remediation: nodePass ? undefined : 'Upgrade to Node.js v20.x or v22.x LTS for full modern feature support.',
    };

    // 2. Configuration Storage & Permissions Check
    const configPath = configManager.getConfigPath();
    const configExists = fs.existsSync(configPath);
    let permPass = true;
    let permDetail = 'Configuration file accessible';

    if (configExists && process.platform !== 'win32') {
      try {
        const stat = fs.statSync(configPath);
        const mode = (stat.mode & 0o777).toString(8);
        if (mode !== '600') {
          permPass = false;
          permDetail = `File mode is 0${mode} (Recommended: 0600)`;
        } else {
          permDetail = 'File mode secured (0600)';
        }
      } catch {
        permPass = false;
        permDetail = 'Unable to check file permissions';
      }
    } else if (configExists) {
      permDetail = 'Present with Windows NTFS ACL control';
    } else {
      permDetail = 'Default configuration in memory (file not yet initialized)';
    }

    checks.configStorage = {
      name: 'Local Credential & Configuration Store',
      pass: true,
      status: permPass ? 'PASS' : 'WARN',
      detail: `${configPath} [${permDetail}]`,
      remediation: permPass ? undefined : `Run: chmod 0600 "${configPath}"`,
    };

    // 3. Backend Reachability & Status
    const client = new ApiClient({
      baseUrl: resolved.apiUrl,
      token: resolved.token,
      orgId: resolved.orgId,
      timeoutMs: Math.min(resolved.timeoutMs, 5000), // Quick probe
    });

    let backendPass = false;
    let backendLatency = 0;
    let backendDetail = '';

    const startTime = Date.now();
    try {
      // First try status endpoint
      const statusRes = await client.get<any>('/status', undefined, { skipAuth: true });
      backendLatency = Date.now() - startTime;
      backendPass = true;
      backendDetail = `Connected to ${resolved.apiUrl} (${backendLatency}ms roundtrip) — ${statusRes.status || statusRes.platform || 'ONLINE'}`;
    } catch {
      // Fallback: try health probe
      try {
        await client.get<any>('/health', undefined, { skipAuth: true });
        backendLatency = Date.now() - startTime;
        backendPass = true;
        backendDetail = `Connected to ${resolved.apiUrl} (${backendLatency}ms roundtrip)`;
      } catch (err: any) {
        backendPass = false;
        backendDetail = `Connection failed to ${resolved.apiUrl}: ${err?.message || 'Host unreachable'}`;
      }
    }

    checks.backendReachability = {
      name: 'Backend API Connectivity',
      pass: backendPass,
      status: backendPass ? 'PASS' : 'FAIL',
      detail: backendDetail,
      remediation: backendPass ? undefined : `Ensure backend server is running at ${resolved.apiUrl} or update config using 'veltrix config set apiUrl <url>'`,
    };

    // 4. Authentication Session Validity
    let authPass = false;
    let authStatus: 'PASS' | 'WARN' | 'FAIL' = 'WARN';
    let authDetail = '';

    if (!resolved.token) {
      authPass = false;
      authStatus = 'WARN';
      authDetail = 'No active authentication token configured';
    } else if (!backendPass) {
      authPass = false;
      authStatus = 'WARN';
      authDetail = 'Cannot verify session because backend is unreachable';
    } else {
      try {
        const meRes = await client.get<ApiResponse<AuthUser>>('/auth/me');
        const user = meRes.data;
        authPass = true;
        authStatus = 'PASS';
        authDetail = `Authenticated as ${user.username} <${user.email}> (Role: ${user.role}, Org: ${user.orgId})`;
      } catch (err: any) {
        authPass = false;
        authStatus = 'FAIL';
        authDetail = `Authentication token invalid or expired: ${err?.message || 'Unauthorized'}`;
      }
    }

    checks.authSession = {
      name: 'Analyst Authentication & RBAC Session',
      pass: authPass,
      status: authStatus,
      detail: authDetail,
      remediation: authPass ? undefined : "Run 'veltrix auth login' to authenticate with your VELTRIX tenant credentials.",
    };

    // Overall Status
    let overallStatus: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY' = 'HEALTHY';
    if (!backendPass || !nodePass) {
      overallStatus = 'UNHEALTHY';
    } else if (!authPass || !permPass) {
      overallStatus = 'DEGRADED';
    }

    if (isJson) {
      out.printJson({
        success: true,
        data: {
          overallStatus,
          timestamp: new Date().toISOString(),
          checks,
        },
      });
      return;
    }

    // Human readable table output
    const checkRows = Object.values(checks).map((chk) => {
      let icon = '✓';
      if (chk.status === 'WARN') icon = '⚠';
      if (chk.status === 'FAIL') icon = '✗';

      return {
        'Status': `${icon} [${chk.status}]`,
        'Diagnostic Check': chk.name,
        'Details': chk.detail,
      };
    });

    out.printTable(checkRows, {
      title: `VELTRIX System Diagnostics — Health: ${overallStatus}`,
    });

    // Print remediations if any
    const remediations = Object.values(checks).filter((c) => c.remediation);
    if (remediations.length > 0) {
      console.log('Actionable Recommendations:');
      for (const r of remediations) {
        console.log(`  • ${r.name}: ${r.remediation}`);
      }
      console.log('');
    }
  });

  return doctorCmd;
}
