import {
  CliError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NetworkError,
  ExitCode,
} from './errors.js';
import { redactSecrets } from '../security/secret-redactor.js';

export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10 MB maximum payload limit

export interface ApiClientOptions {
  baseUrl: string;
  token?: string;
  orgId?: string;
  timeoutMs?: number;
}

export interface RequestOptions {
  params?: Record<string, string | number | boolean | undefined>;
  headers?: Record<string, string>;
  skipAuth?: boolean;
}

export class ApiClient {
  private baseUrl: string;
  private token?: string;
  private orgId?: string;
  private timeoutMs: number;

  constructor(options: ApiClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.token = options.token;
    this.orgId = options.orgId;
    this.timeoutMs = options.timeoutMs ?? 30000;
  }

  public setToken(token: string | undefined): void {
    this.token = token;
  }

  public getToken(): string | undefined {
    return this.token;
  }

  public setOrgId(orgId: string | undefined): void {
    this.orgId = orgId;
  }

  public getOrgId(): string | undefined {
    return this.orgId;
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  /**
   * Performs an HTTP request with timeout, auth headers, tenant isolation, and standardized error normalization.
   */
  public async request<T>(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    endpoint: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<T> {
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    let url = `${this.baseUrl}${cleanEndpoint}`;

    if (options?.params) {
      const searchParams = new URLSearchParams();
      for (const [key, value] of Object.entries(options.params)) {
        if (value !== undefined) {
          searchParams.append(key, String(value));
        }
      }
      const qs = searchParams.toString();
      if (qs) {
        url += (url.includes('?') ? '&' : '?') + qs;
      }
    }

    const headers: Record<string, string> = {
      'Accept': 'application/json',
      ...(options?.headers || {}),
    };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    if (this.token && !options?.skipAuth) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    if (this.orgId) {
      headers['x-organization-id'] = this.orgId;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timer);

      // Guard against unbounded response payload attacks (Finding 3)
      const contentLengthHeader = response.headers.get('content-length');
      if (contentLengthHeader) {
        const contentLength = parseInt(contentLengthHeader, 10);
        if (!isNaN(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
          throw new CliError(
            `Response payload exceeds maximum allowed size (10 MB). Received Content-Length: ${contentLength} bytes.`,
            ExitCode.GENERAL_ERROR,
            'RESPONSE_TOO_LARGE'
          );
        }
      }

      const rawText = await response.text();
      if (rawText.length > MAX_RESPONSE_BYTES) {
        throw new CliError(
          `Response payload exceeds maximum allowed size (10 MB). Received ${rawText.length} bytes.`,
          ExitCode.GENERAL_ERROR,
          'RESPONSE_TOO_LARGE'
        );
      }

      const contentType = response.headers.get('content-type') || '';
      const isJson = contentType.includes('application/json');

      let responseData: any = null;
      if (!rawText.trim()) {
        responseData = {};
      } else if (isJson) {
        try {
          responseData = JSON.parse(rawText);
        } catch (jsonErr) {
          const rawSyntax = jsonErr instanceof Error ? jsonErr.message : String(jsonErr);
          throw new CliError(
            `Malformed JSON response received from backend: ${rawSyntax}`,
            ExitCode.GENERAL_ERROR,
            'MALFORMED_RESPONSE'
          );
        }
      } else {
        responseData = { message: rawText };
      }

      if (!response.ok) {
        this.handleHttpError(response.status, responseData);
      }

      return responseData as T;
    } catch (err: unknown) {
      clearTimeout(timer);

      if (err instanceof CliError) {
        throw err;
      }

      const rawMsg = err instanceof Error ? err.message : String(err);
      const isAbort = (err as Error)?.name === 'AbortError' || rawMsg.includes('aborted');

      if (isAbort) {
        throw new NetworkError(
          `Request to ${this.baseUrl} timed out after ${this.timeoutMs}ms. Check backend latency and connectivity.`,
          'REQUEST_TIMEOUT'
        );
      }

      const sanitizedMsg = redactSecrets(rawMsg);
      throw new NetworkError(
        `Unable to reach VELTRIX backend at ${this.baseUrl}: ${sanitizedMsg}`,
        'CONNECTION_REFUSED'
      );
    }
  }

  private handleHttpError(status: number, data: any): never {
    const errorCode = data?.error?.code || data?.code || `HTTP_${status}`;
    const rawMessage = data?.error?.message || data?.message || `Request failed with status ${status}`;
    const details = data?.error?.details || data?.details;
    const cleanMessage = redactSecrets(String(rawMessage));

    switch (status) {
      case 400:
        throw new ValidationError(cleanMessage, errorCode, details);
      case 401:
        throw new AuthenticationError(
          `${cleanMessage} (Use 'veltrix auth login' or specify valid credentials)`,
          errorCode,
          details
        );
      case 403:
        throw new AuthorizationError(cleanMessage, errorCode, details);
      case 404:
        throw new CliError(cleanMessage, ExitCode.GENERAL_ERROR, errorCode, details);
      case 409:
        throw new ValidationError(cleanMessage, errorCode, details);
      case 429:
        throw new CliError(`Rate limit exceeded: ${cleanMessage}`, ExitCode.GENERAL_ERROR, 'RATE_LIMITED', details);
      default:
        throw new CliError(
          `Server returned error [${status}]: ${cleanMessage}`,
          ExitCode.GENERAL_ERROR,
          errorCode,
          details
        );
    }
  }

  public get<T>(endpoint: string, params?: RequestOptions['params'], options?: RequestOptions): Promise<T> {
    return this.request<T>('GET', endpoint, undefined, { ...options, params });
  }

  public post<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>('POST', endpoint, body, options);
  }

  public patch<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>('PATCH', endpoint, body, options);
  }

  public delete<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return this.request<T>('DELETE', endpoint, undefined, options);
  }
}
