import {
  clearSession,
  getAccessToken,
  getRefreshToken,
  updateTokens,
} from '../auth/session';

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) || '/api/v1';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;

  constructor(message: string, status: number, code = 'API_ERROR', details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

interface ErrorEnvelope {
  error?: { code?: string; message?: string; details?: unknown };
  message?: string;
}

function extractError(payload: unknown, status: number): ApiError {
  const envelope = (payload || {}) as ErrorEnvelope;
  return new ApiError(
    envelope.error?.message || envelope.message || `Request failed with HTTP ${status}`,
    status,
    envelope.error?.code || 'API_ERROR',
    envelope.error?.details
  );
}

async function parseResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json().catch(() => null);
  }
  return response.text().catch(() => null);
}

let refreshInFlight: Promise<boolean> | null = null;

async function refreshSession(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;

  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  refreshInFlight = (async () => {
    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });
      const payload = (await parseResponse(response)) as {
        data?: { accessToken?: string; refreshToken?: string };
      };
      if (!response.ok || !payload?.data?.accessToken) {
        clearSession();
        return false;
      }
      updateTokens(payload.data.accessToken, payload.data.refreshToken);
      return true;
    } catch {
      clearSession();
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

export interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown;
  auth?: boolean;
  raw?: boolean;
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, auth = true, raw = false, headers, ...rest } = options;
  const execute = async (): Promise<Response> => {
    const requestHeaders = new Headers(headers || {});
    if (body !== undefined && !(body instanceof FormData)) {
      requestHeaders.set('Content-Type', 'application/json');
    }
    if (auth) {
      const token = getAccessToken();
      if (token) requestHeaders.set('Authorization', `Bearer ${token}`);
    }
    return fetch(`${API_BASE}${path}`, {
      ...rest,
      headers: requestHeaders,
      body:
        body === undefined
          ? undefined
          : body instanceof FormData
            ? body
            : JSON.stringify(body),
    });
  };

  let response = await execute();
  if (response.status === 401 && auth) {
    const refreshed = await refreshSession();
    if (refreshed) {
      response = await execute();
    }
  }

  const payload = await parseResponse(response);
  if (!response.ok) {
    throw extractError(payload, response.status);
  }

  if (raw) return payload as T;
  return payload as T;
}

export function buildQuery(params: Record<string, unknown> | object): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : '';
}
