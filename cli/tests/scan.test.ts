import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Command } from 'commander';
import { createScanCommand } from '../src/commands/scan.js';
import { ConfigManager } from '../src/config/config-manager.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Scan Command (Scope Authorization & Operations)', () => {
  let tempDir: string;
  let configPath: string;
  let configManager: ConfigManager;
  const originalFetch = global.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veltrix-scan-test-'));
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

  it('rejects unauthenticated request on scan create', async () => {
    const root = new Command();
    root.addCommand(createScanCommand(configManager));
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'scan', 'create', 'site_123']);
    expect(consoleErrorSpy).toHaveBeenCalled();
    const logged = consoleErrorSpy.mock.calls.map((c) => c[0]).join(' ');
    expect(logged).toContain('Authentication required');
  });

  it('enforces scope policy: blocks scan create when target is unauthorized', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_scan_test',
    });

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/websites/site_unverified/scan-authorization')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              siteId: 'site_unverified',
              primaryDomain: 'unverified.example.com',
              status: 'PENDING_VERIFICATION',
              scanBlocked: true,
              authorized: false,
              reason: 'Domain verification token not found in DNS TXT records',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.addCommand(createScanCommand(configManager));
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'scan', 'create', 'site_unverified']);

    expect(consoleErrorSpy).toHaveBeenCalled();
    const logged = consoleErrorSpy.mock.calls.map((c) => c[0]).join(' ');
    expect(logged).toContain('TARGET_UNAUTHORIZED');
    expect(logged).toContain('is NOT authorized for scanning');
  });

  it('honestly reports BACKEND_CAPABILITY_UNAVAILABLE when backend orchestrator (TASK-808) is not deployed (Finding 1)', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_scan_test',
    });

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/websites/site_verified/scan-authorization')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              siteId: 'site_verified',
              primaryDomain: 'verified.example.com',
              status: 'VERIFIED',
              scanBlocked: false,
              authorized: true,
              reason: 'Domain verified',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      // Orchestrator endpoint returns 404 in TASK-808 architectural state
      if (url.includes('/scans')) {
        return new Response(JSON.stringify({ success: false, error: { code: 'NOT_FOUND', message: 'Endpoint not found' } }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createScanCommand(configManager));
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'scan', 'create', 'site_verified', '--json']);

    expect(consoleErrorSpy).toHaveBeenCalled();
    const logged = consoleErrorSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logged);

    expect(parsed.success).toBe(false);
    expect(parsed.error.code).toBe('BACKEND_CAPABILITY_UNAVAILABLE');
    expect(parsed.exitCode).toBe(1);
    expect(parsed.error.details.scanAuthorized).toBe(true);
    expect(parsed.error.details.scanBlocked).toBe(false);
    expect(parsed.error.details.orchestratorStatus).toBe('TASK_808_PENDING_DEPLOYMENT');
  });

  it('successfully returns created scan when backend orchestrator responds 201', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_scan_test',
    });

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/websites/site_verified/scan-authorization')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              siteId: 'site_verified',
              primaryDomain: 'verified.example.com',
              status: 'VERIFIED',
              scanBlocked: false,
              authorized: true,
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (url.includes('/scans')) {
        return new Response(
          JSON.stringify({
            success: true,
            scan: {
              scanId: 'scan_live_999',
              status: 'QUEUED',
              target: 'verified.example.com',
            },
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createScanCommand(configManager));
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'scan', 'create', 'site_verified', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logged = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logged);

    expect(parsed.success).toBe(true);
    expect(parsed.data.scanId).toBe('scan_live_999');
    expect(parsed.data.status).toBe('QUEUED');
  });
});
