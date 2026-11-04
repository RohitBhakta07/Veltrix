import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Command } from 'commander';
import { createFindingsCommand } from '../src/commands/findings.js';
import { ConfigManager } from '../src/config/config-manager.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Findings Command (TDD)', () => {
  let tempDir: string;
  let configPath: string;
  let configManager: ConfigManager;
  const originalFetch = global.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veltrix-findings-test-'));
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

  it('creates commander command with list and show subcommands', () => {
    const cmd = createFindingsCommand(configManager);
    expect(cmd.name()).toBe('findings');
    const subcommands = cmd.commands.map((c) => c.name());
    expect(subcommands).toContain('list');
    expect(subcommands).toContain('show');
  });

  it('rejects unauthenticated request on findings list', async () => {
    const root = new Command();
    root.addCommand(createFindingsCommand(configManager));
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // Parse with no token configured
    await root.parseAsync(['node', 'veltrix', 'findings', 'list']);
    expect(consoleErrorSpy).toHaveBeenCalled();
    const logged = consoleErrorSpy.mock.calls.map((c) => c[0]).join(' ');
    expect(logged).toContain('Authentication required');
  });

  it('lists security incidents and threat findings with --json', async () => {
    // Configure session token
    configManager.saveSession({
      accessToken: 'vltx_tok_findings_test',
      user: {
        userId: 'usr_1',
        username: 'analyst',
        email: 'analyst@test.com',
        role: 'SECURITY_ANALYST',
        orgId: 'org_test_1',
      },
    });

    const mockIncidents = [
      {
        incidentId: 'inc_101',
        title: 'SQL Injection detected on checkout API',
        severity: 'CRITICAL',
        status: 'OPEN',
        siteId: 'site_123',
        createdAt: '2026-11-01T10:00:00Z',
      },
      {
        incidentId: 'inc_102',
        title: 'Cross-Site Scripting (XSS) detected',
        severity: 'HIGH',
        status: 'INVESTIGATING',
        siteId: 'site_123',
        createdAt: '2026-11-01T11:00:00Z',
      },
    ];

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/incidents')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: { items: mockIncidents, total: 2 },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createFindingsCommand(configManager));

    await root.parseAsync(['node', 'veltrix', 'findings', 'list', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const loggedOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(loggedOutput);
    expect(parsed.success).toBe(true);
    expect(parsed.data.total).toBe(2);
    expect(parsed.data.items[0].incidentId).toBe('inc_101');
  });

  it('shows individual finding detail by ID', async () => {
    configManager.saveSession({
      accessToken: 'vltx_tok_findings_test',
    });

    const mockIncidentDetail = {
      incidentId: 'inc_101',
      title: 'SQL Injection detected on checkout API',
      severity: 'CRITICAL',
      status: 'OPEN',
      riskScore: 92,
      siteId: 'site_123',
      affectedTarget: 'https://checkout.example.com/pay',
      summary: 'Automated blind SQL injection probe detected in payload parameters.',
      createdAt: '2026-11-01T10:00:00Z',
    };

    global.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/incidents/inc_101')) {
        return new Response(
          JSON.stringify({
            success: true,
            data: mockIncidentDetail,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ success: false }), { status: 404 });
    });

    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const root = new Command();
    root.option('--json', 'Output JSON');
    root.addCommand(createFindingsCommand(configManager));

    await root.parseAsync(['node', 'veltrix', 'findings', 'show', 'inc_101', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const loggedOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(loggedOutput);
    expect(parsed.success).toBe(true);
    expect(parsed.data.incidentId).toBe('inc_101');
    expect(parsed.data.riskScore).toBe(92);
  });
});
