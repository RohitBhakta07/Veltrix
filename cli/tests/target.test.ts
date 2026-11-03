import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Command } from 'commander';
import { createTargetCommand } from '../src/commands/target.js';
import { ConfigManager } from '../src/config/config-manager.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Target Command (Unit & Security)', () => {
  let tempDir: string;
  let configPath: string;
  let configManager: ConfigManager;
  const originalFetch = global.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veltrix-target-test-'));
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

  it('rejects unauthenticated requests on target list', async () => {
    const root = new Command();
    root.addCommand(createTargetCommand(configManager));
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'target', 'list']);
    expect(consoleErrorSpy).toHaveBeenCalled();
    const logged = consoleErrorSpy.mock.calls.map((c) => c[0]).join(' ');
    expect(logged).toContain('Authentication required');
  });

  it('lists registered targets with status and scan authorization', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_target_test',
    });

    const mockSites = [
      {
        siteId: 'site_alpha',
        primaryDomain: 'app.example.com',
        status: 'VERIFIED',
        scanBlocked: false,
        createdAt: '2026-11-01T00:00:00Z',
      },
      {
        siteId: 'site_beta',
        primaryDomain: 'internal.corp.example',
        status: 'PENDING_VERIFICATION',
        scanBlocked: true,
        createdAt: '2026-11-01T01:00:00Z',
      },
    ];

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/websites')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: mockSites,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createTargetCommand(configManager));
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'target', 'list', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logOutput);

    expect(parsed.success).toBe(true);
    expect(parsed.data.total).toBe(2);
    expect(parsed.data.items[0].primaryDomain).toBe('app.example.com');
  });

  it('checks scan authorization for a specific siteId', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_target_test',
    });

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/websites/site_alpha/scan-authorization')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              siteId: 'site_alpha',
              primaryDomain: 'app.example.com',
              status: 'VERIFIED',
              scanBlocked: false,
              authorized: true,
              reason: 'Domain ownership verified via DNS TXT record.',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createTargetCommand(configManager));
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'target', 'check', 'site_alpha', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logOutput);

    expect(parsed.success).toBe(true);
    expect(parsed.data.authorized).toBe(true);
    expect(parsed.data.scanBlocked).toBe(false);
  });
});

