import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { VeltrixConfigFile, VeltrixProfile, ResolvedCliConfig } from './types.js';

export const DEFAULT_API_URL = 'http://localhost:4000/api/v1';
export const DEFAULT_TIMEOUT_MS = 30000;

export class ConfigManager {
  private configPath: string;

  constructor(customPath?: string) {
    if (customPath) {
      this.configPath = customPath;
    } else if (process.env.VELTRIX_CONFIG_PATH) {
      this.configPath = process.env.VELTRIX_CONFIG_PATH;
    } else {
      const homeDir = os.homedir();
      this.configPath = path.join(homeDir, '.veltrix', 'config.json');
    }
  }

  public getConfigPath(): string {
    return this.configPath;
  }

  /**
   * Initializes a default configuration structure.
   */
  public getDefaultConfig(): VeltrixConfigFile {
    return {
      version: 1,
      currentProfile: 'default',
      profiles: {
        default: {
          apiUrl: DEFAULT_API_URL,
          outputFormat: 'table',
          timeoutMs: DEFAULT_TIMEOUT_MS,
        },
      },
    };
  }

  /**
   * Loads the configuration from disk, creating default if not found.
   */
  public loadConfig(): VeltrixConfigFile {
    try {
      if (!fs.existsSync(this.configPath)) {
        return this.getDefaultConfig();
      }
      const raw = fs.readFileSync(this.configPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || !parsed.profiles) {
        return this.getDefaultConfig();
      }
      return parsed as VeltrixConfigFile;
    } catch {
      return this.getDefaultConfig();
    }
  }

  /**
   * Saves the configuration to disk with restricted permissions (0600).
   */
  public saveConfig(config: VeltrixConfigFile): void {
    const dir = path.dirname(this.configPath);
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      } catch {
        fs.mkdirSync(dir, { recursive: true });
      }
    }

    const payload = JSON.stringify(config, null, 2);
    try {
      fs.writeFileSync(this.configPath, payload, { encoding: 'utf8', mode: 0o600 });
      // Extra chmod safety on POSIX
      if (process.platform !== 'win32') {
        fs.chmodSync(this.configPath, 0o600);
      }
    } catch (err) {
      throw new Error(`Failed to save configuration to ${this.configPath}: ${(err as Error).message}`);
    }
  }

  /**
   * Resolves configuration by applying strict precedence:
   * 1. CLI option flags (--api-url, --token, --json, --org)
   * 2. Environment variables (VELTRIX_API_URL, VELTRIX_TOKEN, VELTRIX_ORG_ID, VELTRIX_OUTPUT)
   * 3. Config file profile values
   * 4. System defaults
   */
  public resolveConfig(cliFlags?: {
    apiUrl?: string;
    token?: string;
    orgId?: string;
    json?: boolean;
    profile?: string;
  }): ResolvedCliConfig {
    const fileExists = fs.existsSync(this.configPath);
    const config = this.loadConfig();
    const profileName = cliFlags?.profile || process.env.VELTRIX_PROFILE || config.currentProfile || 'default';
    const profile: Partial<VeltrixProfile> = config.profiles[profileName] || {};

    // 1. API URL Precedence
    let effectiveApiUrl = DEFAULT_API_URL;
    let apiUrlSource: ResolvedCliConfig['sources']['apiUrl'] = 'default';

    if (cliFlags?.apiUrl) {
      effectiveApiUrl = cliFlags.apiUrl;
      apiUrlSource = 'cli';
    } else if (process.env.VELTRIX_API_URL) {
      effectiveApiUrl = process.env.VELTRIX_API_URL;
      apiUrlSource = 'env';
    } else if (fileExists && profile.apiUrl) {
      effectiveApiUrl = profile.apiUrl;
      apiUrlSource = 'config';
    }

    // 2. Token Precedence
    let effectiveToken: string | undefined = undefined;
    let tokenSource: ResolvedCliConfig['sources']['token'] = 'none';

    const tokenInProfile = profile.token || profile.accessToken;

    if (cliFlags?.token) {
      effectiveToken = cliFlags.token;
      tokenSource = 'cli';
    } else if (process.env.VELTRIX_TOKEN || process.env.VELTRIX_API_KEY) {
      effectiveToken = process.env.VELTRIX_TOKEN || process.env.VELTRIX_API_KEY;
      tokenSource = 'env';
    } else if (fileExists && tokenInProfile) {
      effectiveToken = tokenInProfile;
      tokenSource = 'config';
    }

    // 3. OrgId Precedence
    let effectiveOrgId: string | undefined = undefined;
    let orgIdSource: ResolvedCliConfig['sources']['orgId'] = 'none';

    if (cliFlags?.orgId) {
      effectiveOrgId = cliFlags.orgId;
      orgIdSource = 'cli';
    } else if (process.env.VELTRIX_ORG_ID) {
      effectiveOrgId = process.env.VELTRIX_ORG_ID;
      orgIdSource = 'env';
    } else if (fileExists && (profile.defaultOrgId || profile.orgId || profile.user?.orgId)) {
      effectiveOrgId = profile.defaultOrgId || profile.orgId || profile.user?.orgId;
      orgIdSource = 'config';
    }

    // 4. Output Format Precedence
    let effectiveFormat: 'table' | 'json' = 'table';
    let formatSource: ResolvedCliConfig['sources']['outputFormat'] = 'default';

    if (cliFlags?.json) {
      effectiveFormat = 'json';
      formatSource = 'cli';
    } else if (process.env.VELTRIX_OUTPUT === 'json') {
      effectiveFormat = 'json';
      formatSource = 'env';
    } else if (fileExists && profile.outputFormat) {
      effectiveFormat = profile.outputFormat;
      formatSource = 'config';
    }

    // Normalize API URL (strip trailing slash)
    effectiveApiUrl = effectiveApiUrl.replace(/\/+$/, '');

    return {
      apiUrl: effectiveApiUrl,
      token: effectiveToken,
      orgId: effectiveOrgId,
      outputFormat: effectiveFormat,
      timeoutMs: profile.timeoutMs || DEFAULT_TIMEOUT_MS,
      profileName,
      user: profile.user,
      sources: {
        apiUrl: apiUrlSource,
        token: tokenSource,
        orgId: orgIdSource,
        outputFormat: formatSource,
      },
    };
  }

  /**
   * Saves authenticated session tokens and user info to active profile.
   * Supports both object session payload and legacy positional arguments.
   */
  public saveSession(
    sessionOrToken:
      | string
      | {
          accessToken: string;
          token?: string;
          refreshToken?: string;
          expiresIn?: number;
          user?: VeltrixProfile['user'];
        },
    profileOrUserEmail?: string,
    orgId?: string,
    targetProfile?: string
  ): void {
    const config = this.loadConfig();

    if (typeof sessionOrToken === 'object') {
      const profileKey = targetProfile || profileOrUserEmail || config.currentProfile || 'default';
      if (!config.profiles[profileKey]) {
        config.profiles[profileKey] = {
          apiUrl: DEFAULT_API_URL,
          outputFormat: 'table',
          timeoutMs: DEFAULT_TIMEOUT_MS,
        };
      }

      const prof = config.profiles[profileKey]!;
      prof.accessToken = sessionOrToken.accessToken || sessionOrToken.token;
      prof.token = prof.accessToken;
      prof.refreshToken = sessionOrToken.refreshToken;
      if (sessionOrToken.user) {
        prof.user = sessionOrToken.user;
        prof.defaultOrgId = sessionOrToken.user.orgId;
        prof.orgId = sessionOrToken.user.orgId;
        prof.userEmail = sessionOrToken.user.email;
      }
      if (sessionOrToken.expiresIn) {
        const expiresAt = new Date(Date.now() + sessionOrToken.expiresIn * 1000).toISOString();
        prof.tokenExpiresAt = expiresAt;
      }
      this.saveConfig(config);
    } else {
      // Positional: (token, userEmail, orgId, targetProfile)
      const profileKey = targetProfile || config.currentProfile || 'default';
      if (!config.profiles[profileKey]) {
        config.profiles[profileKey] = {
          apiUrl: DEFAULT_API_URL,
          outputFormat: 'table',
          timeoutMs: DEFAULT_TIMEOUT_MS,
        };
      }
      const prof = config.profiles[profileKey]!;
      prof.accessToken = sessionOrToken;
      prof.token = sessionOrToken;
      if (profileOrUserEmail) {
        prof.userEmail = profileOrUserEmail;
      }
      if (orgId) {
        prof.defaultOrgId = orgId;
        prof.orgId = orgId;
      }
      this.saveConfig(config);
    }
  }

  /**
   * Clears tokens and session details on logout.
   */
  public clearSession(targetProfile?: string): void {
    const config = this.loadConfig();
    const profileKey = targetProfile || config.currentProfile || 'default';

    if (config.profiles[profileKey]) {
      const prof = config.profiles[profileKey]!;
      delete prof.accessToken;
      delete prof.token;
      delete prof.refreshToken;
      delete prof.tokenExpiresAt;
      delete prof.user;
      delete prof.userEmail;
      this.saveConfig(config);
    }
  }

  /**
   * Sets a configuration property on a profile.
   */
  public setConfigValue(key: string, value: string | number, targetProfile?: string): void {
    const allowedKeys = ['apiUrl', 'outputFormat', 'timeoutMs', 'defaultOrgId', 'orgId'];
    if (!allowedKeys.includes(key)) {
      throw new Error(`Unknown configuration key '${key}'. Allowed keys: ${allowedKeys.join(', ')}`);
    }

    const config = this.loadConfig();
    const profileKey = targetProfile || config.currentProfile || 'default';

    if (!config.profiles[profileKey]) {
      config.profiles[profileKey] = {
        apiUrl: DEFAULT_API_URL,
        outputFormat: 'table',
        timeoutMs: DEFAULT_TIMEOUT_MS,
      };
    }

    const prof = config.profiles[profileKey]!;
    if (key === 'timeoutMs') {
      const num = typeof value === 'number' ? value : parseInt(value, 10);
      if (isNaN(num) || num <= 0) {
        throw new Error('Timeout must be a positive integer in milliseconds.');
      }
      prof.timeoutMs = num;
    } else if (key === 'outputFormat') {
      if (value !== 'table' && value !== 'json') {
        throw new Error(`Invalid output format '${value}'. Must be 'table' or 'json'.`);
      }
      prof.outputFormat = value;
    } else if (key === 'apiUrl') {
      prof.apiUrl = String(value);
    } else if (key === 'defaultOrgId' || key === 'orgId') {
      prof.defaultOrgId = String(value);
      prof.orgId = String(value);
    }

    this.saveConfig(config);
  }

  /**
   * Masks tokens safely for terminal presentation without leaking secrets.
   */
  public getMaskedToken(token?: string): string {
    if (!token) return '(none)';
    if (token.length <= 8) return '***';
    const prefix = token.slice(0, 4);
    const suffix = token.slice(-4);
    return `${prefix}...${suffix}`;
  }
}
