import { CliError, ExitCode } from '../client/errors.js';
import { sanitizeObject, redactSecrets } from '../security/secret-redactor.js';
import { formatTable, formatKeyValue, type TableColumn, sanitizeTerminalText } from './table-formatter.js';

export class OutputHandler {
  private isJson: boolean;

  constructor(isJson: boolean = false) {
    this.isJson = isJson;
  }

  public setJson(json: boolean): void {
    this.isJson = json;
  }

  public printJson(data: unknown): void {
    const sanitized = sanitizeObject(data);
    console.log(JSON.stringify(sanitized, null, 2));
  }

  public printInfo(message: string): void {
    if (this.isJson) {
      this.printJson({ success: true, message });
    } else {
      console.log(`ℹ ${sanitizeTerminalText(redactSecrets(message))}`);
    }
  }

  public printTable<T extends Record<string, any>>(
    rows: T[],
    options?: {
      title?: string;
      columns?: TableColumn<T>[];
    }
  ): void {
    if (this.isJson) {
      this.printJson({ success: true, data: rows, total: rows.length });
      return;
    }

    if (options?.title) {
      console.log(`\n=== ${sanitizeTerminalText(options.title)} ===\n`);
    }

    console.log(formatTable(rows, options?.columns));
    console.log('');
  }

  public printData<T>(
    data: T,
    options?: {
      table?: {
        rows: any[];
        columns: TableColumn<any>[];
      };
      summary?: Record<string, unknown>;
      title?: string;
    }
  ): void {
    if (this.isJson) {
      const sanitized = sanitizeObject(data);
      console.log(JSON.stringify(sanitized, null, 2));
      return;
    }

    if (options?.title) {
      console.log(`\n=== ${sanitizeTerminalText(options.title)} ===\n`);
    }

    if (options?.summary) {
      console.log(formatKeyValue(options.summary));
      console.log('');
    }

    if (options?.table) {
      console.log(formatTable(options.table.rows, options.table.columns));
      console.log('');
    } else if (!options?.summary) {
      if (typeof data === 'string') {
        console.log(sanitizeTerminalText(redactSecrets(data)));
      } else if (data && typeof data === 'object') {
        console.log(formatKeyValue(data as Record<string, unknown>));
      }
    }
  }

  public printSuccess(message: string, data?: unknown): void {
    if (this.isJson) {
      const payload = {
        success: true,
        message: redactSecrets(message),
        data: data !== undefined ? sanitizeObject(data) : undefined,
      };
      console.log(JSON.stringify(payload, null, 2));
    } else {
      console.log(`✓ ${sanitizeTerminalText(redactSecrets(message))}`);
      if (data && typeof data === 'object') {
        console.log(formatKeyValue(data as Record<string, unknown>));
      }
    }
  }

  public handleError(err: unknown, exitProcess: boolean = true): void {
    let exitCode = ExitCode.GENERAL_ERROR;
    let message = 'An unexpected error occurred.';
    let code = 'GENERAL_ERROR';
    let details: unknown = undefined;

    if (err instanceof CliError) {
      exitCode = err.exitCode;
      message = err.message;
      code = err.code;
      details = err.details;
    } else if (err instanceof Error) {
      message = err.message;
    } else {
      message = String(err);
    }

    const cleanMsg = redactSecrets(message);

    if (this.isJson) {
      const payload = {
        success: false,
        error: {
          code,
          message: cleanMsg,
          details: details ? sanitizeObject(details) : undefined,
        },
        exitCode,
      };
      console.error(JSON.stringify(payload, null, 2));
    } else {
      console.error(`\n[VELTRIX CLI Error] (${code}): ${sanitizeTerminalText(cleanMsg)}`);
      if (details) {
        console.error(`Details: ${JSON.stringify(sanitizeObject(details))}`);
      }
      console.error('');
    }

    if (exitProcess && !process.env.VELTRIX_NO_EXIT) {
      process.exit(exitCode);
    }
  }
}
