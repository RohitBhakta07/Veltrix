import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ConfigManager, DEFAULT_API_URL } from '../src/config/config-manager.js';

describe('ConfigManager - Precedence and Secure Credential Storage', () => {
  let tempDir: string;
  let tempConfigFile: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veltrix-cfg-test-'));
    tempConfigFile = path.join(tempDir, 'config.json');

    // Clean env vars before each test
    delete process.env.VELTRIX_API_URL;
    delete process.env.VELTRIX_TOKEN;
    delete process.env.VELTRIX_ORG_ID;
    delete process.env.VELTRIX_PROFILE;
    delete process.env.VELTRIX_OUTPUT;
  });

  afterEach(() => {
    try {
      if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    } catch {
      // ignore cleanup errors
    }
  });

  describe('Configuration Precedence', () => {
    it('resolves defaults when no file, env, or CLI flags exist', () => {
      const manager = new ConfigManager(tempConfigFile);
      const resolved = manager.resolveConfig();

      expect(resolved.apiUrl).toBe(DEFAULT_API_URL);
      expect(resolved.sources.apiUrl).toBe('default');
      expect(resolved.outputFormat).toBe('table');
      expect(resolved.token).toBeUndefined();
    });

    it('prefers config file profile values over defaults', () => {
      const manager = new ConfigManager(tempConfigFile);
      manager.saveConfig({
        version: 1,
        currentProfile: 'default',
        profiles: {
          default: {
            apiUrl: 'https://api.cloud.veltrix.internal/v1',
            outputFormat: 'json',
            timeoutMs: 45000,
            token: 'vltx_tok_file_token',
          },
        },
      });

      const resolved = manager.resolveConfig();
      expect(resolved.apiUrl).toBe('https://api.cloud.veltrix.internal/v1');
      expect(resolved.sources.apiUrl).toBe('config');
      expect(resolved.outputFormat).toBe('json');
      expect(resolved.token).toBe('vltx_tok_file_token');
      expect(resolved.sources.token).toBe('config');
    });

    it('prefers environment variables over config file profile', () => {
      const manager = new ConfigManager(tempConfigFile);
      manager.saveConfig({
        version: 1,
        currentProfile: 'default',
        profiles: {
          default: {
            apiUrl: 'https://from-config.com/v1',
            token: 'token-from-config',
          },
        },
      });

      process.env.VELTRIX_API_URL = 'https://from-env.com/api/v1';
      process.env.VELTRIX_TOKEN = 'vltx_tok_from_env';
      process.env.VELTRIX_ORG_ID = 'org_from_env';

      const resolved = manager.resolveConfig();
      expect(resolved.apiUrl).toBe('https://from-env.com/api/v1');
      expect(resolved.sources.apiUrl).toBe('env');
      expect(resolved.token).toBe('vltx_tok_from_env');
      expect(resolved.sources.token).toBe('env');
      expect(resolved.orgId).toBe('org_from_env');
    });

    it('prefers CLI flags over environment variables and config files', () => {
      const manager = new ConfigManager(tempConfigFile);
      manager.saveConfig({
        version: 1,
        currentProfile: 'default',
        profiles: {
          default: {
            apiUrl: 'https://from-config.com/v1',
            token: 'token-from-config',
          },
        },
      });

      process.env.VELTRIX_API_URL = 'https://from-env.com/api/v1';
      process.env.VELTRIX_TOKEN = 'vltx_tok_from_env';

      const resolved = manager.resolveConfig({
        apiUrl: 'https://override-from-cli.com/v1',
        token: 'vltx_tok_cli_flag',
        json: true,
      });

      expect(resolved.apiUrl).toBe('https://override-from-cli.com/v1');
      expect(resolved.sources.apiUrl).toBe('cli');
      expect(resolved.token).toBe('vltx_tok_cli_flag');
      expect(resolved.sources.token).toBe('cli');
      expect(resolved.outputFormat).toBe('json');
    });
  });

  describe('Session Management & Credential Security', () => {
    it('saves session and clears session cleanly', () => {
      const manager = new ConfigManager(tempConfigFile);
      manager.saveSession('vltx_tok_session_12345', 'analyst@veltrix.com', 'org_corp_01');

      let cfg = manager.loadConfig();
      expect(cfg.profiles.default?.token).toBe('vltx_tok_session_12345');
      expect(cfg.profiles.default?.userEmail).toBe('analyst@veltrix.com');
      expect(cfg.profiles.default?.orgId).toBe('org_corp_01');

      manager.clearSession();
      cfg = manager.loadConfig();
      expect(cfg.profiles.default?.token).toBeUndefined();
      expect(cfg.profiles.default?.userEmail).toBeUndefined();
    });

    it('saves session object to specified profile and preserves profile isolation', () => {
      const manager = new ConfigManager(tempConfigFile);
      manager.saveSession(
        {
          accessToken: 'vltx_tok_staging_token_999',
          refreshToken: 'vltx_tok_staging_refresh_999',
          expiresIn: 3600,
          user: {
            userId: 'user-staging-1',
            username: 'staging_analyst',
            email: 'staging@corp.internal',
            role: 'SECURITY_ANALYST',
            orgId: 'org-staging-corp',
          },
        },
        'staging'
      );

      const cfg = manager.loadConfig();
      expect(cfg.profiles.staging).toBeDefined();
      expect(cfg.profiles.staging?.token).toBe('vltx_tok_staging_token_999');
      expect(cfg.profiles.staging?.user?.username).toBe('staging_analyst');
      expect(cfg.profiles.default?.token).toBeUndefined();
    });

    it('masks tokens safely for terminal presentation', () => {
      const manager = new ConfigManager(tempConfigFile);
      expect(manager.getMaskedToken(undefined)).toBe('(none)');
      expect(manager.getMaskedToken('short')).toBe('***');
      expect(manager.getMaskedToken('vltx_tok_1234567890abcdef')).toBe('vltx...cdef');
    });

    it('sets configuration keys with valid validation', () => {
      const manager = new ConfigManager(tempConfigFile);
      manager.setConfigValue('apiUrl', 'https://custom-target.internal/v1');
      manager.setConfigValue('outputFormat', 'json');
      manager.setConfigValue('timeoutMs', '15000');

      const resolved = manager.resolveConfig();
      expect(resolved.apiUrl).toBe('https://custom-target.internal/v1');
      expect(resolved.outputFormat).toBe('json');
      expect(resolved.timeoutMs).toBe(15000);
    });

    it('rejects invalid configuration keys and values', () => {
      const manager = new ConfigManager(tempConfigFile);
      expect(() => manager.setConfigValue('unsupportedKey', 'val')).toThrow('Unknown configuration key');
      expect(() => manager.setConfigValue('outputFormat', 'xml')).toThrow("Invalid output format 'xml'");
      expect(() => manager.setConfigValue('timeoutMs', '-5')).toThrow('Timeout must be a positive integer');
    });
  });
});

