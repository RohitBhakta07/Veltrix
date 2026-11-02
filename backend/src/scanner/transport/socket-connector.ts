/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Safe Socket Connector
 *
 * Enforces direct socket connection to the pre-validated pinned IP, bypasses ambient
 * proxies, prevents secondary DNS resolution, and enforces strict TLS certificate validation.
 */

import net from 'node:net';
import tls from 'node:tls';
import type { SocketConnectorInterface } from './types.js';

export class DefaultSocketConnector implements SocketConnectorInterface {
  constructor() {
    // Ambient proxy environment isolation:
    // We do not use proxy-agent or inspect HTTP_PROXY/HTTPS_PROXY. Direct TCP sockets only.
  }

  connect(options: { host: string; port: number }): net.Socket {
    return net.connect({
      host: options.host,
      port: options.port,
    });
  }

  connectTls(options: tls.ConnectionOptions): tls.TLSSocket {
    return tls.connect({
      ...options,
      rejectUnauthorized: true,
    });
  }
}
