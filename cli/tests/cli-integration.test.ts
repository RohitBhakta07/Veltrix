import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createCli } from '../src/index.js';
import { ConfigManager } from '../src/config/config-manager.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('CLI Integration & Command Tree', () => {
  let tempDir: string;
  let configPath: string;
  const originalFetch = global.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veltrix-cli-test-'));
    configPath = path.join(tempDir, 'config.json');
    process.env.VELTRIX_CONFIG_PATH = configPath;
    process.env.VELTRIX_NO_EXIT = 'true';
    delete process.env.VELTRIX_TOKEN;
    delete process.env.VELTRIX_API_URL;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    delete process.env.VELTRIX_CONFIG_PATH;
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

  it('initializes root CLI program with all required subcommands', () => {
    const cli = createCli();
    expect(cli.name()).toBe('veltrix');

    const commands = cli.commands.map((c) => c.name());
    expect(commands).toContain('auth');
    expect(commands).toContain('config');
    expect(commands).toContain('target');
    expect(commands).toContain('scan');
    expect(commands).toContain('findings');
    expect(commands).toContain('doctor');
    expect(commands).toContain('status');
  });

  it('rejects loopback target on target validate with SSRF error', async () => {
    const cli = createCli();
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await cli.parseAsync(['node', 'veltrix', 'target', 'validate', 'http://127.0.0.1:8080']);

    expect(consoleErrorSpy).toHaveBeenCalled();
    const errOutput = consoleErrorSpy.mock.calls.map((c) => c[0]).join(' ');
    expect(errOutput).toContain('PROHIBITED_DESTINATION');
    expect(errOutput).toContain('private, loopback, or cloud-metadata');
  });

  it('rejects cloud metadata target on target validate', async () => {
    const cli = createCli();
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await cli.parseAsync(['node', 'veltrix', 'target', 'validate', 'http://169.254.169.254/latest/meta-data/']);

    expect(consoleErrorSpy).toHaveBeenCalled();
    const errOutput = consoleErrorSpy.mock.calls.map((c) => c[0]).join(' ');
    expect(errOutput).toContain('PROHIBITED_DESTINATION');
  });

  it('validates benign target URL with --json output', async () => {
    const cli = createCli();
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await cli.parseAsync(['node', 'veltrix', 'target', 'validate', 'https://example.com', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logOutput);

    expect(parsed.success).toBe(true);
    expect(parsed.data.inputTarget).toBe('https://example.com');
    expect(parsed.data.domain).toBe('example.com');
  });

  it('executes config show with masked secret presentation', async () => {
    const manager = new ConfigManager(configPath);
    manager.saveSession({
      accessToken: 'vltx_tok_super_secret_token_123',
    });

    const cli = createCli();
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await cli.parseAsync(['node', 'veltrix', 'config', 'show']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');

    // Should NOT print raw token
    expect(logOutput).not.toContain('vltx_tok_super_secret_token_123');
    // Should contain active status
    expect(logOutput).toContain('CONFIGURED / ACTIVE');
  });

  it('executes status command and reports operational status', async () => {
    const cli = createCli();
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    await cli.parseAsync(['node', 'veltrix', 'status', '--json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const logOutput = consoleLogSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(logOutput);

    expect(parsed.status).toBe('READY');
    expect(parsed.platform).toContain('VELTRIX');
  });
});
