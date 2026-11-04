/**
 * VELTRIX CLI — Typed Error Hierarchy & Exit Codes
 */

export enum ExitCode {
  SUCCESS = 0,
  GENERAL_ERROR = 1,
  VALIDATION_ERROR = 2,
  AUTH_ERROR = 3,
  FORBIDDEN_ERROR = 4,
  FORBIDDEN = 4,
  NETWORK_ERROR = 5,
  SCOPE_ERROR = 6,
  SCOPE_POLICY_ERROR = 6,
}

export class CliError extends Error {
  public readonly exitCode: ExitCode;
  public readonly code: string;
  public readonly details?: unknown;

  constructor(message: string, exitCode: ExitCode = ExitCode.GENERAL_ERROR, code: string = 'CLI_ERROR', details?: unknown) {
    super(message);
    this.name = 'CliError';
    this.exitCode = exitCode;
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ValidationError extends CliError {
  constructor(message: string, code: string = 'VALIDATION_FAILED', details?: unknown) {
    super(message, ExitCode.VALIDATION_ERROR, code, details);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends CliError {
  constructor(message: string, code: string = 'UNAUTHORIZED', details?: unknown) {
    super(message, ExitCode.AUTH_ERROR, code, details);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends CliError {
  constructor(message: string, code: string = 'FORBIDDEN', details?: unknown) {
    super(message, ExitCode.FORBIDDEN_ERROR, code, details);
    this.name = 'AuthorizationError';
  }
}

export class NetworkError extends CliError {
  constructor(message: string, code: string = 'NETWORK_ERROR', details?: unknown) {
    super(message, ExitCode.NETWORK_ERROR, code, details);
    this.name = 'NetworkError';
  }
}

export class ScopePolicyError extends CliError {
  constructor(message: string, code: string = 'SCOPE_POLICY_VIOLATION', details?: unknown) {
    super(message, ExitCode.SCOPE_ERROR, code, details);
    this.name = 'ScopePolicyError';
  }
}
