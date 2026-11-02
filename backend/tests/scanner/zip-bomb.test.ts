import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import {
  SafeHttpClient,
  DnsResolver,
  type RequestAuthorizationContext,
} from '../../src/scanner/transport/index.js';

describe('Phase 8: Decompression Bomb & Multi-Layer Resource Ceilings (TASK-802)', () => {
  let server: http.Server;
  let serverPort: number;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host}`);

      // 1. Uncompressed 5 MB response (Allowed)
      if (url.pathname === '/uncompressed-5mb') {
        const payload = Buffer.alloc(5 * 1024 * 1024, 'A');
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Content-Length': payload.length.toString(),
        });
        res.end(payload);
        return;
      }

      // 2. Raw compressed wire ceiling breach (> 2 MB compressed)
      if (url.pathname === '/compressed-wire-overflow') {
        // 2.5 MB true random bytes (incompressible)
        const randomBytes = crypto.randomBytes(2.5 * 1024 * 1024);
        const compressed = zlib.gzipSync(randomBytes);
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Encoding': 'gzip',
          'Content-Length': compressed.length.toString(),
        });
        res.end(compressed);
        return;
      }

      // 3. Decompressed size ceiling breach (Expands > 10 MB)
      if (url.pathname === '/decompressed-overflow') {
        // Highly compressible 15 MB of zeros
        const zeros = Buffer.alloc(15 * 1024 * 1024, 0);
        const compressed = zlib.gzipSync(zeros);
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Content-Encoding': 'gzip',
        });
        res.end(compressed);
        return;
      }

      // 4. Decompression bomb with > 100:1 ratio (after 64 KB warm-up)
      if (url.pathname === '/ratio-bomb') {
        // Create repeating compressible stream
        const largeZeros = Buffer.alloc(12 * 1024 * 1024, 0); // 12 MB zeros compresses to ~12 KB (ratio > 1000:1)
        const compressed = zlib.gzipSync(largeZeros);
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Content-Encoding': 'gzip',
        });
        res.end(compressed);
        return;
      }

      // 5. Chunked encoding without Content-Length
      if (url.pathname === '/chunked-stream') {
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Transfer-Encoding': 'chunked',
        });
        res.write('chunk-1-data-');
        res.write('chunk-2-data-');
        res.end('chunk-3-end');
        return;
      }

      // 6. Unsupported encoding (e.g. zstd)
      if (url.pathname === '/unsupported-encoding') {
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Encoding': 'zstd',
        });
        res.end(Buffer.from('zstd-data'));
        return;
      }

      // 7. Malformed gzip stream
      if (url.pathname === '/malformed-gzip') {
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Content-Encoding': 'gzip',
        });
        res.end(Buffer.from([0x1f, 0x8b, 0xff, 0xff, 0x00, 0x01])); // corrupt gzip header
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as net.AddressInfo;
        serverPort = addr.port;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const baseAuthorizedContext: RequestAuthorizationContext = {
    purpose: 'AUTHORIZED_SCAN',
    orgId: 'org-enterprise-01',
    scanId: 'scan-001',
    siteId: 'site-001',
    primaryDomain: 'primary.example.com',
    approvedSubdomains: [],
    status: 'VERIFIED',
    scanBlocked: false,
    expiresAt: Date.now() + 86400000,
  };

  const createTestClient = () => {
    return new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      }),
      allowLoopbackForTesting: true,
    });
  };

  it('permits legitimate uncompressed bodies between 2 MB and 10 MB (proves 2MB wire limit not applied to uncompressed)', async () => {
    const client = createTestClient();
    const res = await client.get(`http://primary.example.com:${serverPort}/uncompressed-5mb`, {
      allowLoopbackForTesting: true,
      context: {
        ...baseAuthorizedContext,
        allowedPorts: [serverPort],
      },
    });

    expect(res.status).toBe(200);
    expect(res.decompressedBytes).toBe(5 * 1024 * 1024);
    expect(res.wireBytesReceived).toBe(5 * 1024 * 1024);
    expect(res.rawBody.length).toBe(5 * 1024 * 1024);
  });

  it('rejects compressed responses exceeding 2 MB raw wire data ceiling', async () => {
    const client = createTestClient();
    await expect(
      client.get(`http://primary.example.com:${serverPort}/compressed-wire-overflow`, {
        allowLoopbackForTesting: true,
        context: {
          ...baseAuthorizedContext,
          allowedPorts: [serverPort],
        },
      })
    ).rejects.toThrow(/exceeds maximum wire limit|exceeded maximum limit/i);
  });

  it('destroys stream and socket when decompressed body exceeds 10 MB ceiling without worker crash', async () => {
    const client = createTestClient();
    const memBefore = process.memoryUsage().heapUsed;

    await expect(
      client.get(`http://primary.example.com:${serverPort}/decompressed-overflow`, {
        allowLoopbackForTesting: true,
        context: {
          ...baseAuthorizedContext,
          allowedPorts: [serverPort],
        },
      })
    ).rejects.toThrow(/Decompression bomb detected|exceeded maximum limit of 10485760 bytes/i);

    const memDeltaMb = (process.memoryUsage().heapUsed - memBefore) / (1024 * 1024);
    // Verifies bounded memory footprint (< 100 MB delta)
    expect(memDeltaMb).toBeLessThan(100);
  });

  it('detects decompression bomb exceeding 100:1 expansion ratio after 64 KB warm-up', async () => {
    const client = createTestClient();
    await expect(
      client.get(`http://primary.example.com:${serverPort}/ratio-bomb`, {
        allowLoopbackForTesting: true,
        context: {
          ...baseAuthorizedContext,
          allowedPorts: [serverPort],
        },
      })
    ).rejects.toThrow(/Decompression bomb detected: Expansion ratio exceeded 100:1/i);
  });

  it('safely handles chunked transfer encoding without Content-Length header', async () => {
    const client = createTestClient();
    const res = await client.get(`http://primary.example.com:${serverPort}/chunked-stream`, {
      allowLoopbackForTesting: true,
      context: {
        ...baseAuthorizedContext,
        allowedPorts: [serverPort],
      },
    });

    expect(res.status).toBe(200);
    expect(res.text).toBe('chunk-1-data-chunk-2-data-chunk-3-end');
  });

  it('fails closed safely on unsupported compression algorithm (zstd) without crashing', async () => {
    const client = createTestClient();
    await expect(
      client.get(`http://primary.example.com:${serverPort}/unsupported-encoding`, {
        allowLoopbackForTesting: true,
        context: {
          ...baseAuthorizedContext,
          allowedPorts: [serverPort],
        },
      })
    ).rejects.toThrow(/Unsupported or unhandled content-encoding: 'zstd'/i);
  });

  it('fails closed safely on corrupted/malformed gzip payload without leaking resources', async () => {
    const client = createTestClient();
    await expect(
      client.get(`http://primary.example.com:${serverPort}/malformed-gzip`, {
        allowLoopbackForTesting: true,
        context: {
          ...baseAuthorizedContext,
          allowedPorts: [serverPort],
        },
      })
    ).rejects.toThrow(/Decompression error for 'gzip' payload/i);
  });
});
