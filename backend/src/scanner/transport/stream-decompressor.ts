/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Streaming Decompression Guard
 *
 * Enforces independent wire and decompressed size limits, continuous streaming byte accounting,
 * 100:1 decompression bomb detection, and fail-closed handling of malformed encodings.
 */

import type http from 'node:http';
import zlib from 'node:zlib';
import { SafeTransportError } from './types.js';

export const MAX_COMPRESSED_WIRE_BYTES = 2 * 1024 * 1024; // 2 MB
export const MAX_DECOMPRESSED_BODY_BYTES = 10 * 1024 * 1024; // 10 MB
export const MAX_EXPANSION_RATIO = 100; // 100:1 ratio
export const EXPANSION_WARMUP_BYTES = 64 * 1024; // 64 KB warm-up threshold

export interface DecompressedResponseResult {
  bodyBuffer: Buffer;
  wireBytesReceived: number;
  decompressedBytes: number;
  contentEncoding: string;
}

export class StreamDecompressor {
  static async consumeStream(
    res: http.IncomingMessage,
    options?: {
      maxWireBytes?: number;
      maxDecompressedBytes?: number;
    }
  ): Promise<DecompressedResponseResult> {
    const rawEncoding = (res.headers['content-encoding'] || '').trim().toLowerCase();
    const isCompressed = rawEncoding === 'gzip' || rawEncoding === 'deflate' || rawEncoding === 'br';
    const isIdentity = !rawEncoding || rawEncoding === 'identity';

    if (!isCompressed && !isIdentity) {
      // Safely reject unsupported compression algorithms (e.g. zstd)
      try {
        res.destroy();
      } catch {}
      throw new SafeTransportError(
        'UNSUPPORTED_ENCODING',
        `Unsupported or unhandled content-encoding: '${rawEncoding}'.`
      );
    }

    const maxWireLimit = isCompressed
      ? options?.maxWireBytes ?? MAX_COMPRESSED_WIRE_BYTES
      : options?.maxDecompressedBytes ?? MAX_DECOMPRESSED_BODY_BYTES;

    const maxDecompressedLimit = options?.maxDecompressedBytes ?? MAX_DECOMPRESSED_BODY_BYTES;

    // Check declared Content-Length header pre-flight if present
    const rawContentLength = res.headers['content-length'];
    if (rawContentLength) {
      const declaredLength = parseInt(rawContentLength, 10);
      if (!isNaN(declaredLength)) {
        if (isCompressed && declaredLength > maxWireLimit) {
          try {
            res.destroy();
          } catch {}
          throw new SafeTransportError(
            'MAX_RESPONSE_SIZE_EXCEEDED',
            `Declared compressed content-length (${declaredLength} bytes) exceeds maximum wire limit of ${maxWireLimit} bytes.`
          );
        }
        if (!isCompressed && declaredLength > maxDecompressedLimit) {
          try {
            res.destroy();
          } catch {}
          throw new SafeTransportError(
            'MAX_RESPONSE_SIZE_EXCEEDED',
            `Declared content-length (${declaredLength} bytes) exceeds maximum response body limit of ${maxDecompressedLimit} bytes.`
          );
        }
      }
    }

    let wireBytesReceived = 0;
    let decompressedBytes = 0;
    const bodyChunks: Buffer[] = [];

    return new Promise<DecompressedResponseResult>((resolve, reject) => {
      let settled = false;

      const fail = (err: SafeTransportError) => {
        if (settled) return;
        settled = true;
        try {
          res.destroy();
        } catch {}
        try {
          res.socket?.destroy();
        } catch {}
        reject(err);
      };

      if (!isCompressed) {
        // Identity / Uncompressed stream processing
        res.on('data', (chunk: Buffer) => {
          wireBytesReceived += chunk.length;
          decompressedBytes += chunk.length;

          if (decompressedBytes > maxDecompressedLimit) {
            fail(
              new SafeTransportError(
                'MAX_RESPONSE_SIZE_EXCEEDED',
                `Uncompressed response body exceeded maximum limit of ${maxDecompressedLimit} bytes.`
              )
            );
            return;
          }

          bodyChunks.push(chunk);
        });

        res.on('end', () => {
          if (settled) return;
          settled = true;
          resolve({
            bodyBuffer: Buffer.concat(bodyChunks),
            wireBytesReceived,
            decompressedBytes,
            contentEncoding: 'identity',
          });
        });

        res.on('error', (err) => {
          fail(
            new SafeTransportError(
              'UNSUPPORTED_ENCODING',
              `Stream transfer error: ${(err as Error)?.message || 'Unknown network stream error'}`
            )
          );
        });
        return;
      }

      // Compressed stream processing
      let decompressorStream: zlib.Gunzip | zlib.Inflate | zlib.BrotliDecompress;
      if (rawEncoding === 'gzip') {
        decompressorStream = zlib.createGunzip();
      } else if (rawEncoding === 'deflate') {
        decompressorStream = zlib.createInflate();
      } else {
        decompressorStream = zlib.createBrotliDecompress();
      }

      // Monitor raw incoming wire chunks
      res.on('data', (chunk: Buffer) => {
        wireBytesReceived += chunk.length;

        if (wireBytesReceived > maxWireLimit) {
          try {
            decompressorStream.destroy();
          } catch {}
          fail(
            new SafeTransportError(
              'MAX_RESPONSE_SIZE_EXCEEDED',
              `Compressed wire data exceeded maximum limit of ${maxWireLimit} bytes.`
            )
          );
          return;
        }

        try {
          decompressorStream.write(chunk);
        } catch (writeErr) {
          fail(
            new SafeTransportError(
              'UNSUPPORTED_ENCODING',
              `Failed writing chunk to decompressor: ${(writeErr as Error)?.message}`
            )
          );
        }
      });

      res.on('end', () => {
        try {
          decompressorStream.end();
        } catch {}
      });

      res.on('error', (err) => {
        try {
          decompressorStream.destroy();
        } catch {}
        fail(
          new SafeTransportError(
            'UNSUPPORTED_ENCODING',
            `Incoming response stream error: ${(err as Error)?.message}`
          )
        );
      });

      // Monitor decompressed output chunks
      decompressorStream.on('data', (chunk: Buffer) => {
        decompressedBytes += chunk.length;

        if (decompressedBytes > maxDecompressedLimit) {
          try {
            decompressorStream.destroy();
          } catch {}
          fail(
            new SafeTransportError(
              'MAX_RESPONSE_SIZE_EXCEEDED',
              `Decompressed response body exceeded maximum limit of ${maxDecompressedLimit} bytes.`
            )
          );
          return;
        }

        // Enforce 100:1 decompression bomb check after warm-up
        if (decompressedBytes >= EXPANSION_WARMUP_BYTES) {
          const ratio = decompressedBytes / (wireBytesReceived || 1);
          if (ratio > MAX_EXPANSION_RATIO) {
            try {
              decompressorStream.destroy();
            } catch {}
            fail(
              new SafeTransportError(
                'DECOMPRESSION_BOMB_DETECTED',
                `Decompression bomb detected: Expansion ratio exceeded ${MAX_EXPANSION_RATIO}:1 (decompressed: ${decompressedBytes} bytes, compressed wire: ${wireBytesReceived} bytes).`
              )
            );
            return;
          }
        }

        bodyChunks.push(chunk);
      });

      decompressorStream.on('end', () => {
        if (settled) return;
        settled = true;
        resolve({
          bodyBuffer: Buffer.concat(bodyChunks),
          wireBytesReceived,
          decompressedBytes,
          contentEncoding: rawEncoding,
        });
      });

      decompressorStream.on('error', (err) => {
        fail(
          new SafeTransportError(
            'UNSUPPORTED_ENCODING',
            `Decompression error for '${rawEncoding}' payload: ${(err as Error)?.message}`
          )
        );
      });
    });
  }
}
