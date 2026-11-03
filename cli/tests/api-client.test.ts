import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ApiClient } from '../src/client/api-client.js';
import {
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NetworkError,
  CliError,
  ExitCode,
} from '../src/client/errors.js';

describe('ApiClient - Network Security and Error Normalization', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('injects Bearer token in Authorization header when token is present', async () => {
    let capturedHeaders: HeadersInit | undefined;

    global.fetch = vi.fn().mockImplementation(async (_url, init) => {
      capturedHeaders = init?.headers;
      return new Response(JSON.stringify({ success: true, data: { status: 'ok' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    const client = new ApiClient({
      baseUrl: 'http://localhost:4000/api/v1',
      token: 'vltx_tok_mock_test_123',
    });

    const res = await client.get<{ success: boolean; data: { status: string } }>('/status');
    expect(res.success).toBe(true);
    expect(capturedHeaders).toBeDefined();
    expect((capturedHeaders as Record<string, string>)['Authorization']).toBe(
      'Bearer vltx_tok_mock_test_123'
    );
  });

  it('skips Authorization header when skipAuth is true', async () => {
    let capturedHeaders: HeadersInit | undefined;

    global.fetch = vi.fn().mockImplementation(async (_url, init) => {
      capturedHeaders = init?.headers;
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    const client = new ApiClient({
      baseUrl: 'http://localhost:4000/api/v1',
      token: 'vltx_tok_mock_test_123',
    });

    await client.get('/public', undefined, { skipAuth: true });
    expect((capturedHeaders as Record<string, string>)['Authorization']).toBeUndefined();
  });

  it('converts HTTP 400 Bad Request to ValidationError (ExitCode 2)', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          success: false,
          error: { code: 'INVALID_DOMAIN', message: 'Target domain malformed' },
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const client = new ApiClient({ baseUrl: 'http://localhost:4000/api/v1' });

    try {
      await client.post('/websites', { domain: 'invalid' });
      expect.fail('Should have thrown ValidationError');
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      expect((err as ValidationError).exitCode).toBe(ExitCode.VALIDATION_ERROR);
      expect((err as ValidationError).code).toBe('INVALID_DOMAIN');
      expect((err as ValidationError).message).toContain('Target domain malformed');
    }
  });

  it('converts HTTP 401 Unauthorized to AuthenticationError (ExitCode 3)', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          success: false,
          error: { code: 'TOKEN_EXPIRED', message: 'JWT access token expired' },
        }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const client = new ApiClient({ baseUrl: 'http://localhost:4000/api/v1' });

    try {
      await client.get('/auth/me');
      expect.fail('Should have thrown AuthenticationError');
    } catch (err) {
      expect(err).toBeInstanceOf(AuthenticationError);
      expect((err as AuthenticationError).exitCode).toBe(ExitCode.AUTH_ERROR);
      expect((err as AuthenticationError).code).toBe('TOKEN_EXPIRED');
    }
  });

  it('converts HTTP 403 Forbidden to AuthorizationError (ExitCode 4)', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          success: false,
          error: { code: 'FORBIDDEN', message: 'Insufficient tenant role permissions' },
        }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const client = new ApiClient({ baseUrl: 'http://localhost:4000/api/v1' });

    try {
      await client.post('/detections/run', {});
      expect.fail('Should have thrown AuthorizationError');
    } catch (err) {
      expect(err).toBeInstanceOf(AuthorizationError);
      expect((err as AuthorizationError).exitCode).toBe(ExitCode.FORBIDDEN);
    }
  });

  it('converts connection timeout to NetworkError (ExitCode 5)', async () => {
    global.fetch = vi.fn().mockImplementation(
      () =>
        new Promise((_, reject) => {
          const abortErr = new Error('The operation was aborted');
          abortErr.name = 'AbortError';
          setTimeout(() => reject(abortErr), 50);
        })
    );

    const client = new ApiClient({
      baseUrl: 'http://localhost:4000/api/v1',
      timeoutMs: 10,
    });

    try {
      await client.get('/websites');
      expect.fail('Should have timed out');
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkError);
      expect((err as NetworkError).exitCode).toBe(ExitCode.NETWORK_ERROR);
      expect((err as NetworkError).code).toBe('REQUEST_TIMEOUT');
    }
  });

  it('redacts sensitive tokens in error messages', async () => {
    global.fetch = vi.fn().mockImplementation(async () => {
      throw new Error(
        'Failed connecting with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.sig to host'
      );
    });

    const client = new ApiClient({ baseUrl: 'http://localhost:4000/api/v1' });

    try {
      await client.get('/test');
      expect.fail('Should have failed');
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkError);
      const msg = (err as NetworkError).message;
      expect(msg).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(msg).toContain('Bearer [REDACTED]');
    }
  });

  it('injects x-organization-id header when orgId is configured (Finding 4)', async () => {
    let capturedHeaders: HeadersInit | undefined;

    global.fetch = vi.fn().mockImplementation(async (_url, init) => {
      capturedHeaders = init?.headers;
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    const client = new ApiClient({
      baseUrl: 'http://localhost:4000/api/v1',
      token: 'vltx_tok_mock',
      orgId: 'org_cyber_command',
    });

    await client.get('/status');
    expect(capturedHeaders).toBeDefined();
    expect((capturedHeaders as Record<string, string>)['x-organization-id']).toBe(
      'org_cyber_command'
    );
  });

  it('rejects oversized responses exceeding 10 MB payload limit (Finding 3)', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: 'huge' }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': '15728640', // 15 MB
        },
      })
    );

    const client = new ApiClient({ baseUrl: 'http://localhost:4000/api/v1' });

    try {
      await client.get('/huge-data');
      expect.fail('Should have thrown RESPONSE_TOO_LARGE');
    } catch (err) {
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).code).toBe('RESPONSE_TOO_LARGE');
    }
  });

  it('maps JSON syntax errors to MALFORMED_RESPONSE (Finding 3)', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response('<html><body>502 Bad Gateway</body></html>', {
        status: 502,
        headers: { 'Content-Type': 'application/json' }, // Server sent HTML with JSON header
      })
    );

    const client = new ApiClient({ baseUrl: 'http://localhost:4000/api/v1' });

    try {
      await client.get('/bad-gateway');
      expect.fail('Should have thrown MALFORMED_RESPONSE');
    } catch (err) {
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).code).toBe('MALFORMED_RESPONSE');
    }
  });

  it('handles empty response bodies (e.g. HTTP 204 No Content) gracefully without syntax errors', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(null, {
        status: 204,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const client = new ApiClient({ baseUrl: 'http://localhost:4000/api/v1' });
    const res = await client.delete<any>('/websites/site-123');
    expect(res).toEqual({});
  });

  it('rejects chunked payloads exceeding 10 MB limit even when Content-Length header is omitted', async () => {
    // Generate an oversized string > 10MB without Content-Length
    const largeChunk = 'x'.repeat(11 * 1024 * 1024);
    global.fetch = vi.fn().mockResolvedValue(
      new Response(largeChunk, {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Transfer-Encoding': 'chunked',
          // Note: Content-Length is omitted in chunked transfers
        },
      })
    );

    const client = new ApiClient({ baseUrl: 'http://localhost:4000/api/v1' });

    try {
      await client.get('/stream-huge');
      expect.fail('Should have thrown RESPONSE_TOO_LARGE');
    } catch (err) {
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).code).toBe('RESPONSE_TOO_LARGE');
    }
  });
});

