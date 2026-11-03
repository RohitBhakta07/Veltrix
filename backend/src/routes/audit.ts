import { Router, type Request, type Response } from 'express';
import type { ApiErrorResponse, ApiResponse, AuditLog } from '@veltrix/shared';
import { authenticate, requireBearerAuth } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import type { StorageInterface } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';

interface AuditLedgerPayload {
  entries: AuditLog[];
  total: number;
  chain: { verified: boolean; length: number; brokenRecordId?: string };
}

/**
 * GET /api/v1/audit
 * Tenant-scoped audit ledger plus SHA-256 hash-chain verification state.
 * Read-only by design: the ledger is append-only and never mutated over HTTP.
 */
export function createAuditRouter(storage?: StorageInterface): Router {
  const router = Router();
  const store = storage || getStorage();

  router.use(requireBearerAuth);
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  const respond = async (req: Request, res: Response) => {
    try {
      const orgId = req.tenantOrgId!;
      const limit = Math.min(500, Math.max(1, Number.parseInt(String(req.query.limit || '200'), 10) || 200));

      const [entries, chain] = await Promise.all([
        store.getAuditLogs(orgId, limit),
        store.verifyAuditChain(orgId),
      ]);

      const response: ApiResponse<AuditLedgerPayload> = {
        success: true,
        data: {
          entries,
          total: entries.length,
          chain,
        },
        meta: { timestamp: new Date().toISOString(), total: entries.length },
      };
      res.status(200).json(response);
    } catch (err: unknown) {
      console.error('[VELTRIX] Audit ledger query error:', err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: { code: 'STORAGE_QUERY_ERROR', message: 'Failed to read the audit ledger' },
      };
      res.status(500).json(errorResponse);
    }
  };

  router.get('/', respond);
  router.get('/verify', respond);

  return router;
}
