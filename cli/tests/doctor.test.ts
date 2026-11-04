import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Command } from 'commander';
import { createDoctorCommand } from '../src/commands/doctor.js';
import { ConfigManager } from '../src/config/config-manager.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Doctor Command (TDD)', () => {
  let tempDir: string;
  let configPath: string;
  let configManager: ConfigManager;
  const originalFetch = global.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veltrix-doctor-test-'));
    configPath = path.join(tempDir, 'config.json');
    configManager = new ConfigManager(configPath);
    process.env.VELTRIX_NO_EXIT = 'true';
    delete process.env.VELTRIX_TOKEN;
    delete process.env.VELTRIX_API_URL;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    delete process.env.VELTRIX_NO_EXIT;
    global.fetch = originalFetch;
    try {
      if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    } catch {
      // ignore
    }
  });

  it('creates commander command for doctor', () => {
    const cmd = createDoctorCommand(configManager);
    expect(cmd.name()).toBe('doctor');
  });

  it('runs complete diagnostic checks in healthy authenticated state with --json', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_doctor_healthy',
      user: {
        userId: 'usr_doc_1',
        username: 'lead_architect',
        email: 'architect@veltrix.com',
        role: 'ORG_ADMIN',
        orgId: 'org_main',
      },
    });

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/status') || url.includes('/health')) {
        return new Response(
          JSON.stringify({
            platform: 'VELTRIX Security Platform',
            version: '1.0.0',
            status: 'READY',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (url.includes('/auth/me')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              userId: 'usr_doc_1',
              username: 'lead_architect',
              email: 'architect@veltrix.com',
              role: 'ORG_ADMIN',
              orgId: 'org_main',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createDoctorCommand(configManager));

    await root.parseAsync(['node', 'veltrix', 'doctor', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const loggedOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(loggedOutput);

    expect(parsed.success).toBe(true);
    expect(parsed.data.overallStatus).toBe('HEALTHY');
    expect(parsed.data.checks.nodeRuntime.pass).toBe(true);
    expect(parsed.data.checks.backendReachability.pass).toBe(true);
    expect(parsed.data.checks.authSession.pass).toBe(true);
  });

  it('reports degraded status when backend is reachable but unauthenticated', async () => {
    // No session saved in configManager

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/status') || url.includes('/health')) {
        return new Response(
          JSON.stringify({
            platform: 'VELTRIX Security Platform',
            version: '1.0.0',
            status: 'READY',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createDoctorCommand(configManager));

    await root.parseAsync(['node', 'veltrix', 'doctor', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const loggedOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(loggedOutput);

    expect(parsed.success).toBe(true);
    expect(parsed.data.overallStatus).toBe('DEGRADED');
    expect(parsed.data.checks.backendReachability.pass).toBe(true);
    expect(parsed.data.checks.authSession.pass).toBe(false);
  });
});

