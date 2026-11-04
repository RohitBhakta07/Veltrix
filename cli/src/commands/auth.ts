import { Command } from 'commander';
import readline from 'node:readline';
import { ApiClient } from '../client/api-client.js';
import { ConfigManager } from '../config/config-manager.js';
import { OutputHandler } from '../formatters/output.js';
import { ValidationError, AuthenticationError } from '../client/errors.js';
import type { ApiResponse, AuthSession, AuthUser } from '@veltrix/shared';

function promptText(question: string, hidden: boolean = false): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    if (hidden && process.stdin.isTTY) {
      // Mask password entry in terminal
      process.stdout.write(question);
      let password = '';
      const oldRaw = process.stdin.isRaw;
      process.stdin.setRawMode(true);
      process.stdin.resume();

      const onData = (char: Buffer) => {
        const c = char.toString('utf8');
        if (c === '\n' || c === '\r' || c === '\u0004') {
          process.stdin.setRawMode(oldRaw);
          process.stdin.removeListener('data', onData);
          rl.close();
          process.stdout.write('\n');
          resolve(password.trim());
        } else if (c === '\u0003') {
          process.exit(1);
        } else if (c === '\b' || c === '\x7f') {
          if (password.length > 0) {
            password = password.slice(0, -1);
            process.stdout.write('\b \b');
          }
        } else {
          password += c;
          process.stdout.write('*');
        }
      };

      process.stdin.on('data', onData);
    } else {
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    }
  });
}

export function createAuthCommand(configManager: ConfigManager): Command {
  const authCmd = new Command('auth');
  authCmd.description('Authenticate and manage analyst session credentials (login, status, refresh, logout)');

  // Login
  authCmd
    .command('login')
    .description('Authenticate analyst using email and password to obtain JWT session token')
    .option('--email <email>', 'Analyst email address')
    .option('--password <password>', 'Analyst password (avoid passing via CLI flags; use prompt or VELTRIX_PASSWORD)')
    .option('--org <orgId>', 'Tenant organization context')
    .action(async (options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = options.json || resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      const client = new ApiClient({
        baseUrl: resolved.apiUrl,
        timeoutMs: resolved.timeoutMs,
      });

      try {
        let email = options.email || process.env.VELTRIX_EMAIL;
        let password = options.password || process.env.VELTRIX_PASSWORD;
        const orgId = options.org || resolved.orgId;

        // Security warning if password passed directly in CLI flags
        if (options.password && !isJson) {
          console.error(
            '\n[SECURITY WARNING] Passing passwords via CLI flags exposes secrets in process listings and shell history.\nPrefer interactive prompt or VELTRIX_PASSWORD environment variable.\n'
          );
        }

        if (!email) {
          if (!process.stdin.isTTY) {
            throw new ValidationError('Email is required. Set VELTRIX_EMAIL or provide token authentication in non-interactive environments.');
          }
          email = await promptText('Analyst Email: ');
        }

        if (!password) {
          if (!process.stdin.isTTY) {
            throw new ValidationError(
              'Password is required. Set VELTRIX_PASSWORD environment variable or provide token via VELTRIX_TOKEN in non-interactive environments.'
            );
          }
          password = await promptText('Password: ', true);
        }

        if (!email || !password) {
          throw new ValidationError('Email and password cannot be empty.');
        }

        const loginRes = await client.post<ApiResponse<AuthSession>>(
          '/auth/login',
          {
            email,
            password,
            orgId: orgId || undefined,
          },
          { skipAuth: true }
        );

        if (!loginRes.success || !loginRes.data) {
          throw new AuthenticationError('Login failed: invalid response from authentication provider.');
        }

        const session = loginRes.data;
        const accessToken = (session as any).tokens?.accessToken || (session as any).accessToken;
        const refreshToken = (session as any).tokens?.refreshToken || (session as any).refreshToken;
        const expiresIn = (session as any).tokens?.expiresIn || (session as any).expiresIn;
        const user = session.user;

        configManager.saveSession(
          {
            accessToken,
            refreshToken,
            expiresIn,
            user,
          },
          resolved.profileName
        );

        out.printSuccess(`Successfully authenticated as ${user.username} (${user.role})`, {
          userId: user.userId,
          username: user.username,
          email: user.email,
          role: user.role,
          orgId: user.orgId,
          expiresIn: expiresIn ? `${expiresIn}s` : undefined,
        });
      } catch (err) {
        out.handleError(err);
      }
    });

  // Refresh Token
  authCmd
    .command('refresh')
    .description('Rotate and refresh JWT access token using stored refresh token')
    .action(async (_options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      const cfg = configManager.loadConfig();
      const prof = cfg.profiles[resolved.profileName] || {};
      const refreshToken = prof.refreshToken || process.env.VELTRIX_REFRESH_TOKEN;

      if (!refreshToken) {
        out.handleError(
          new AuthenticationError(
            "No refresh token available. Run 'veltrix auth login' to establish a new authenticated session.",
            'NO_REFRESH_TOKEN'
          )
        );
        return;
      }

      const client = new ApiClient({
        baseUrl: resolved.apiUrl,
        timeoutMs: resolved.timeoutMs,
      });

      try {
        const refreshRes = await client.post<ApiResponse<{ accessToken: string; refreshToken?: string; expiresIn?: number }>>(
          '/auth/refresh',
          { refreshToken },
          { skipAuth: true }
        );

        const tokens = refreshRes.data;
        configManager.saveSession(
          {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken || refreshToken,
            expiresIn: tokens.expiresIn,
            user: resolved.user,
          },
          resolved.profileName
        );

        out.printSuccess('Session token successfully refreshed.', {
          profile: resolved.profileName,
          expiresIn: tokens.expiresIn ? `${tokens.expiresIn}s` : undefined,
        });
      } catch (err) {
        out.handleError(err);
      }
    });

  // Status (me)
  authCmd
    .command('status')
    .description('Display current authentication state and active operator identity')
    .action(async (_options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      if (!resolved.token) {
        if (isJson) {
          out.printJson({
            authenticated: false,
            message: "No active session found. Authenticate using 'veltrix auth login'.",
          });
          return;
        }
        out.printInfo("No active session found. Authenticate using 'veltrix auth login' or provide --token / VELTRIX_TOKEN.");
        return;
      }

      const client = new ApiClient({
        baseUrl: resolved.apiUrl,
        token: resolved.token,
        orgId: resolved.orgId,
        timeoutMs: resolved.timeoutMs,
      });

      try {
        const meRes = await client.get<ApiResponse<AuthUser>>('/auth/me');
        const user = meRes.data;

        out.printData(user, {
          title: 'Active Operator Identity',
          summary: {
            'Authenticated': 'YES',
            'User ID': user.userId,
            'Username': user.username,
            'Email': user.email,
            'Role': user.role,
            'Tenant Org ID': user.orgId,
            'Token Source': resolved.sources.token,
            'API Target': resolved.apiUrl,
          },
        });
      } catch (err) {
        out.handleError(err);
      }
    });

  // Logout
  authCmd
    .command('logout')
    .description('Terminate current session, invalidate tokens on server, and purge local credentials')
    .action(async (_options, cmd) => {
      const globalOpts = cmd.optsWithGlobals();
      const resolved = configManager.resolveConfig(globalOpts);
      const isJson = resolved.outputFormat === 'json';
      const out = new OutputHandler(isJson);

      if (!resolved.token) {
        configManager.clearSession(resolved.profileName);
        out.printSuccess('Session cleared locally (no active server token existed).');
        return;
      }

      const client = new ApiClient({
        baseUrl: resolved.apiUrl,
        token: resolved.token,
        orgId: resolved.orgId,
        timeoutMs: resolved.timeoutMs,
      });

      try {
        // Attempt backend invalidation
        try {
          await client.post('/auth/logout');
        } catch {
          // Non-blocking if server unreachable; still purge locally
        }

        configManager.clearSession(resolved.profileName);
        out.printSuccess('Successfully logged out. Session tokens purged from local configuration.');
      } catch (err) {
        out.handleError(err);
      }
    });

  return authCmd;
}
