import fs from 'node:fs';
import { Command } from 'commander';
import { ConfigManager } from '../config/config-manager.js';
import { OutputHandler } from '../formatters/output.js';
import { ValidationError } from '../client/errors.js';

export function createConfigCommand(configManager: ConfigManager): Command {
  const configCmd = new Command('config');
  configCmd.description('Inspect, validate, and manage local CLI configuration profiles');

  // Show
  configCmd
    .command('show')
    .description('Display effective configuration settings and their resolution sources')
    .action((_options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const out = new OutputHandler(resolved.outputFormat === 'json');

      const configPath = configManager.getConfigPath();
      const fileExists = fs.existsSync(configPath);

      const displayData = {
        profile: resolved.profileName,
        apiUrl: resolved.apiUrl,
        apiUrlSource: resolved.sources.apiUrl,
        defaultOrgId: resolved.orgId || '(not set)',
        orgIdSource: resolved.sources.orgId,
        outputFormat: resolved.outputFormat,
        outputFormatSource: resolved.sources.outputFormat,
        timeoutMs: resolved.timeoutMs,
        tokenStatus: resolved.token ? '[CONFIGURED / ACTIVE]' : '[NONE]',
        tokenSource: resolved.sources.token,
        user: resolved.user ? `${resolved.user.username} (${resolved.user.role})` : '(unauthenticated)',
        configFile: configPath,
        configFileExists: fileExists,
      };

      out.printData(displayData, {
        title: `Configuration Profile: ${resolved.profileName}`,
        summary: {
          'Active Profile': resolved.profileName,
          'API Target': `${resolved.apiUrl} (via ${resolved.sources.apiUrl})`,
          'Organization ID': `${resolved.orgId || '-'} (via ${resolved.sources.orgId})`,
          'Output Format': `${resolved.outputFormat} (via ${resolved.sources.outputFormat})`,
          'Request Timeout': `${resolved.timeoutMs}ms`,
          'Token Status': `${displayData.tokenStatus} (via ${resolved.sources.token})`,
          'Active Operator': displayData.user,
          'Config Storage': `${configPath} [${fileExists ? 'Present' : 'Not Created'}]`,
        },
      });
    });

  // Set
  configCmd
    .command('set <key> <value>')
    .description('Update a configuration parameter for the active profile')
    .action((key, value, _options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const out = new OutputHandler(resolved.outputFormat === 'json');

      const allowedKeys = ['apiUrl', 'outputFormat', 'timeoutMs', 'defaultOrgId'] as const;
      if (!allowedKeys.includes(key as any)) {
        out.handleError(
          new ValidationError(
            `Invalid configuration key '${key}'. Permitted keys: ${allowedKeys.join(', ')}.`
          )
        );
        return;
      }

      try {
        configManager.setConfigValue(key as any, value, resolved.profileName);
        out.printSuccess(`Updated '${key}' = '${value}' on profile '${resolved.profileName}'.`);
      } catch (err) {
        out.handleError(err);
      }
    });

  // Validate
  configCmd
    .command('validate')
    .description('Validate configuration file syntax, permissions, and values')
    .action((_options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const out = new OutputHandler(resolved.outputFormat === 'json');

      const configPath = configManager.getConfigPath();
      const issues: string[] = [];

      if (!fs.existsSync(configPath)) {
        out.printSuccess('Configuration file not found (using default fallback settings). All values valid.');
        return;
      }

      try {
        const stats = fs.statSync(configPath);
        if (process.platform !== 'win32') {
          const mode = stats.mode & 0o777;
          if (mode > 0o600) {
            issues.push(`Insecure file permissions: ${mode.toString(8)} (should be 0600)`);
          }
        }

        const raw = fs.readFileSync(configPath, 'utf8');
        const parsed = JSON.parse(raw);
        if (!parsed.profiles || typeof parsed.profiles !== 'object') {
          issues.push("Missing 'profiles' object in configuration file.");
        }

        try {
          new URL(resolved.apiUrl);
        } catch {
          issues.push(`Configured API URL '${resolved.apiUrl}' is not a valid URL.`);
        }

        if (issues.length > 0) {
          out.handleError(new ValidationError(`Configuration validation failed: ${issues.join('; ')}`));
          return;
        }

        out.printSuccess('Configuration file is syntactically valid and securely stored.', {
          path: configPath,
          profilesCount: Object.keys(parsed.profiles || {}).length,
          activeProfile: resolved.profileName,
        });
      } catch (err) {
        out.handleError(new ValidationError(`Failed to validate configuration: ${(err as Error).message}`));
      }
    });

  return configCmd;
}

