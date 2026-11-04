import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Command } from 'commander';
import { createAuthCommand } from '../src/commands/auth.js';
import { ConfigManager } from '../src/config/config-manager.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Auth Command (Unit & Security)', () => {
  let tempDir: string;
  let configPath: string;
  let configManager: ConfigManager;
  const originalFetch = global.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veltrix-auth-test-'));
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

  it('reports unauthenticated status on auth status when no token is present', async () => {
    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createAuthCommand(configManager));
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'auth', 'status', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logOutput);

    expect(parsed.authenticated).toBe(false);
  });

  it('performs login and stores access token and user session', async () => {
    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/auth/login')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              tokens: {
                accessToken: 'vltx_tok_login_successful_123',
                refreshToken: 'vltx_tok_refresh_456',
                expiresIn: 3600,
              },
              user: {
                userId: 'usr_sec_1',
                username: 'sec_admin',
                email: 'admin@sec.veltrix.internal',
                role: 'ORG_ADMIN',
                orgId: 'org_sec_ops',
              },
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createAuthCommand(configManager));
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await root.parseAsync([
      'node',
      'veltrix',
      'auth',
      'login',
      '--email',
      'admin@sec.veltrix.internal',
      '--password',
      'SafePassword123!',
      '--json',
    ]);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logOutput);

    expect(parsed.success).toBe(true);
    expect(parsed.data.username).toBe('sec_admin');

    // Verify token was stored in profile
    const cfg = configManager.loadConfig();
    expect(cfg.profiles.default?.accessToken).toBe('vltx_tok_login_successful_123');
  });

  it('performs logout, calls backend invalidation, and removes local token', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_to_be_purged',
      user: {
        userId: 'usr_1',
        username: 'analyst',
        email: 'analyst@test.com',
        role: 'SECURITY_ANALYST',
        orgId: 'org_1',
      },
    });

    let logoutCalled = false;
    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/auth/logout')) {
        logoutCalled = true;
        return new Response(JSON.stringify({ success: true, message: 'Logged out' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createAuthCommand(configManager));
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'auth', 'logout', '--json']);

    expect(logoutCalled).toBe(true);
    const cfg = configManager.loadConfig();
    expect(cfg.profiles.default?.accessToken).toBeUndefined();
  });

  it('supports non-interactive login via VELTRIX_PASSWORD env var without CLI flag (Finding 2)', async () => {
    process.env.VELTRIX_EMAIL = 'ci_agent@veltrix.internal';
    process.env.VELTRIX_PASSWORD = 'EnvVarPassword123!';

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/auth/login')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              tokens: {
                accessToken: 'vltx_tok_env_login',
                refreshToken: 'vltx_tok_env_refresh',
                expiresIn: 3600,
              },
              user: {
                userId: 'usr_ci_1',
                username: 'ci_runner',
                email: 'ci_agent@veltrix.internal',
                role: 'SECURITY_ANALYST',
                orgId: 'org_ci',
              },
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createAuthCommand(configManager));
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    // Call login without any --email or --password flags!
    await root.parseAsync(['node', 'veltrix', 'auth', 'login', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logOutput);

    expect(parsed.success).toBe(true);
    expect(parsed.data.username).toBe('ci_runner');
    const cfg = configManager.loadConfig();
    expect(cfg.profiles.default?.accessToken).toBe('vltx_tok_env_login');

    delete process.env.VELTRIX_EMAIL;
    delete process.env.VELTRIX_PASSWORD;
  });

  it('performs token rotation via auth refresh (Finding 5)', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_old_access',
      refreshToken: 'vltx_tok_old_refresh',
      user: {
        userId: 'usr_1',
        username: 'analyst',
        email: 'analyst@test.com',
        role: 'SECURITY_ANALYST',
        orgId: 'org_1',
      },
    });

    let refreshCalled = false;
    global.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.includes('/auth/refresh')) {
        refreshCalled = true;
        const body = JSON.parse(init?.body as string);
        expect(body.refreshToken).toBe('vltx_tok_old_refresh');

        return new Response(
          JSON.stringify({
            success: true,
            data: {
              accessToken: 'vltx_tok_new_rotated_access',
              refreshToken: 'vltx_tok_new_rotated_refresh',
              expiresIn: 7200,
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createAuthCommand(configManager));
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await root.parseAsync(['node', 'veltrix', 'auth', 'refresh', '--json']);

    expect(refreshCalled).toBe(true);
    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logOutput);

    expect(parsed.success).toBe(true);
    const cfg = configManager.loadConfig();
    expect(cfg.profiles.default?.accessToken).toBe('vltx_tok_new_rotated_access');
    expect(cfg.profiles.default?.refreshToken).toBe('vltx_tok_new_rotated_refresh');
  });
});
