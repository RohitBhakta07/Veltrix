import { Command } from 'commander';
import dotenv from 'dotenv';
import { PLATFORM_INFO } from '@veltrix/shared';
import { ConfigManager } from './config/config-manager.js';
import { createAuthCommand } from './commands/auth.js';
import { createConfigCommand } from './commands/config.js';
import { createTargetCommand } from './commands/target.js';
import { createScanCommand } from './commands/scan.js';
import { createFindingsCommand } from './commands/findings.js';
import { createDoctorCommand } from './commands/doctor.js';
import { OutputHandler } from './formatters/output.js';
import { redactSecrets } from './security/secret-redactor.js';

dotenv.config();

export function createCli(customConfigManager?: ConfigManager): Command {
  const configManager = customConfigManager || new ConfigManager();
  const program = new Command();

  program
    .name('veltrix')
    .description(`${PLATFORM_INFO.name} — ${PLATFORM_INFO.tagline}\nHigh-performance SOC terminal operator interface & security scanning suite.`)
    .version(PLATFORM_INFO.version)
    .option('-u, --api-url <url>', 'Override target VELTRIX backend API URL')
    .option('-t, --token <token>', 'Authentication Bearer token or API key')
    .option('-o, --org <orgId>', 'Tenant organization context ID')
    .option('-p, --profile <name>', 'Active configuration profile name')
    .option('--json', 'Output machine-readable JSON')
    .showHelpAfterError('(run "veltrix --help" for available commands)');

  // 1. Auth Subcommands (login, status, logout)
  program.addCommand(createAuthCommand(configManager));

  // 2. Config Subcommands (show, set, validate)
  program.addCommand(createConfigCommand(configManager));

  // 3. Target Scope Subcommands (validate, list, add, check, verify)
  program.addCommand(createTargetCommand(configManager));

  // 4. Scan Subcommands (create, status, cancel)
  program.addCommand(createScanCommand(configManager));

  // 5. Findings Subcommands (list, show)
  program.addCommand(createFindingsCommand(configManager));

  // 6. Platform Diagnostics Doctor Subcommand
  program.addCommand(createDoctorCommand(configManager));

  // 7. Status Command (Platform and connectivity baseline)
  program
    .command('status')
    .description('Check platform operational status and backend connectivity')
    .option('--json', 'Output raw JSON')
    .action(async (options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = options.json || resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      try {
        const statusData = {
          platform: PLATFORM_INFO.name,
          version: PLATFORM_INFO.version,
          tagline: PLATFORM_INFO.tagline,
          status: 'READY',
          profile: resolved.profileName,
          backendUrl: resolved.apiUrl,
          backendSource: resolved.sources.apiUrl,
          tokenStatus: resolved.token ? '[CONFIGURED]' : '[NONE]',
        };

        if (isJson) {
          out.printJson(statusData);
        } else {
          out.printData(statusData, {
            title: `${statusData.platform} Status`,
            summary: {
              'Platform': statusData.platform,
              'Version': statusData.version,
              'Operational Status': statusData.status,
              'Active Profile': statusData.profile,
              'API Target': `${statusData.backendUrl} (${statusData.backendSource})`,
              'Authentication': statusData.tokenStatus,
            },
          });
        }
      } catch (err) {
        out.handleError(err);
      }
    });

  return program;
}

// Global exception safety with secret sanitization
process.on('unhandledRejection', (reason) => {
  const msg = reason instanceof Error ? reason.message : String(reason);
  console.error('[VELTRIX CLI Unhandled Rejection]:', redactSecrets(msg));
  if (!process.env.VELTRIX_NO_EXIT) {
    process.exit(1);
  }
});

process.on('uncaughtException', (err) => {
  const msg = err instanceof Error ? err.stack || err.message : String(err);
  console.error('[VELTRIX CLI Uncaught Exception]:', redactSecrets(msg));
  if (!process.env.VELTRIX_NO_EXIT) {
    process.exit(1);
  }
});

// Direct execution guard
if (
  process.argv[1]?.endsWith('index.js') ||
  process.argv[1]?.endsWith('index.ts')
) {
  const cli = createCli();
  cli.parse(process.argv);
}
