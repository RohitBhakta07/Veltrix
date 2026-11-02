/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Tenant-Scoped Active Socket Registry
 *
 * Implements strict tenant-isolated socket tracking, deterministic lifecycle cleanup,
 * and high-resolution emergency abort satisfying the sub-500ms SLO.
 */

import type net from 'node:net';
import type tls from 'node:tls';

export type TrackedSocket = net.Socket | tls.TLSSocket;

export class ActiveSocketRegistry {
  // Two-level nested Map prevents delimiter collisions across arbitrary orgId and scanId values:
  // orgId -> scanId -> Set<TrackedSocket>
  private readonly registry = new Map<string, Map<string, Set<TrackedSocket>>>();

  // Tracks scan scopes currently in an active abort state to prevent race conditions
  // where a socket is registered while abort is executing.
  private readonly abortedScans = new Set<string>();

  private buildScanKey(orgId: string, scanId: string): string {
    return `${encodeURIComponent(orgId)}::${encodeURIComponent(scanId)}`;
  }

  /**
   * Registers an active socket under a trusted tenant organization and scan ID.
   * Returns an idempotent unregister callback.
   */
  register(
    orgId: string,
    scanId: string,
    socket: TrackedSocket
  ): () => void {
    if (!orgId || !scanId || !socket) {
      return () => {};
    }

    const scanKey = this.buildScanKey(orgId, scanId);

    // If this scan has been aborted, immediately destroy incoming socket to prevent race conditions
    if (this.abortedScans.has(scanKey)) {
      try {
        socket.destroy();
      } catch {}
      return () => {};
    }

    let orgMap = this.registry.get(orgId);
    if (!orgMap) {
      orgMap = new Map();
      this.registry.set(orgId, orgMap);
    }

    let socketSet = orgMap.get(scanId);
    if (!socketSet) {
      socketSet = new Set();
      orgMap.set(scanId, socketSet);
    }

    socketSet.add(socket);

    let unregistered = false;
    const unregister = () => {
      if (unregistered) return;
      unregistered = true;

      const currentOrgMap = this.registry.get(orgId);
      if (!currentOrgMap) return;

      const currentSet = currentOrgMap.get(scanId);
      if (currentSet) {
        currentSet.delete(socket);
        if (currentSet.size === 0) {
          currentOrgMap.delete(scanId);
        }
      }

      if (currentOrgMap.size === 0) {
        this.registry.delete(orgId);
      }
    };

    // Auto-cleanup on normal close, timeout, or error
    socket.once('close', unregister);
    socket.once('error', unregister);

    return unregister;
  }

  /**
   * Terminates all active sockets for a specific tenant and scan within < 500 ms SLO.
   * Completely isolated: never affects another tenant or another scan in the same organization.
   */
  abortScan(orgId: string, scanId: string): number {
    if (!orgId || !scanId) return 0;

    const scanKey = this.buildScanKey(orgId, scanId);
    this.abortedScans.add(scanKey);

    // Automatically expire the abort race marker after 15 seconds
    setTimeout(() => {
      this.abortedScans.delete(scanKey);
    }, 15000).unref?.();

    const orgMap = this.registry.get(orgId);
    if (!orgMap) return 0;

    const socketSet = orgMap.get(scanId);
    if (!socketSet || socketSet.size === 0) return 0;

    let abortedCount = 0;
    const sockets = Array.from(socketSet);

    // Destroy all active sockets immediately
    for (const socket of sockets) {
      try {
        socket.destroy(new Error(`Scan aborted for organization '${orgId}', scan '${scanId}'.`));
        abortedCount++;
      } catch {}
    }

    socketSet.clear();
    orgMap.delete(scanId);

    if (orgMap.size === 0) {
      this.registry.delete(orgId);
    }

    return abortedCount;
  }

  /**
   * Emergency process-wide abort.
   * Reserved strictly for host shutdown or unrecoverable container emergency.
   */
  abortAllSockets(): number {
    let abortedCount = 0;
    for (const [, orgMap] of this.registry) {
      for (const [, socketSet] of orgMap) {
        for (const socket of socketSet) {
          try {
            socket.destroy(new Error('Process-wide emergency socket abort initiated.'));
            abortedCount++;
          } catch {}
        }
        socketSet.clear();
      }
      orgMap.clear();
    }
    this.registry.clear();
    this.abortedScans.clear();
    return abortedCount;
  }

  /**
   * Returns active socket count, optionally filtered by orgId and scanId.
   */
  getActiveCount(orgId?: string, scanId?: string): number {
    if (orgId && scanId) {
      return this.registry.get(orgId)?.get(scanId)?.size || 0;
    }
    if (orgId) {
      let count = 0;
      const orgMap = this.registry.get(orgId);
      if (orgMap) {
        for (const set of orgMap.values()) {
          count += set.size;
        }
      }
      return count;
    }

    let total = 0;
    for (const orgMap of this.registry.values()) {
      for (const set of orgMap.values()) {
        total += set.size;
      }
    }
    return total;
  }
}

export const defaultActiveSocketRegistry = new ActiveSocketRegistry();
