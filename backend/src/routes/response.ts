import { Router, type Request, type Response } from 'express';
import type {
  ApiErrorResponse,
  ApiResponse,
  ResponseExecution,
} from '@veltrix/shared';
import { authenticate, requireBearerAuth } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import type { StorageInterface } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';
import { generateUuidV7 } from '../utils/uuid.js';

interface ResponseQueuePayload {
  executions: ResponseExecution[];
  total: number;
  counts: Record<string, number>;
}

function summarize(executions: ResponseExecution[]): Record<string, number> {
  const counts: Record<string, number> = {
    PENDING_APPROVAL: 0,
    APPROVED: 0,
    EXECUTED: 0,
    FAILED: 0,
    ROLLED_BACK: 0,
    REJECTED: 0,
  };
  for (const execution of executions) {
    counts[execution.status] = (counts[execution.status] || 0) + 1;
  }
  return counts;
}

/**
 * Approval-gated defensive response queue (SOAR).
 *
 * Every mutation is simulated (`isSimulated: true`) and appended to the
 * tamper-evident audit ledger, so the console can demonstrate the full
 * request → approve → execute → roll back lifecycle without touching real
 * infrastructure.
 */
export function createResponseRouter(storage?: StorageInterface): Router {
  const router = Router();
  const store = storage || getStorage();

  router.use(requireBearerAuth);
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  const audit = async (
    req: Request,
    action: 'RESPONSE_APPROVED' | 'RESPONSE_EXECUTED' | 'RESPONSE_ROLLED_BACK',
    details: Record<string, unknown>
  ) => {
    const orgId = req.tenantOrgId!;
    await store.appendAuditLog({
      logId: generateUuidV7(),
      orgId,
      timestamp: new Date().toISOString(),
      action,
      actor: {
        userId: req.user?.userId || 'unknown',
        role: req.user?.role || 'READ_ONLY_VIEWER',
        ipAddress: req.ip,
      },
      details,
    });
  };

  // GET /api/v1/response — full queue with lifecycle counts.
  router.get('/', async (req: Request, res: Response) => {
    try {
      const orgId = req.tenantOrgId!;
      const incidentId = (req.query.incidentId as string | undefined) || undefined;
      const executions = await store.listExecutions(orgId, incidentId);

      const payload: ApiResponse<ResponseQueuePayload> = {
        success: true,
        data: {
          executions,
          total: executions.length,
          counts: summarize(executions),
        },
        meta: { timestamp: new Date().toISOString(), total: executions.length },
      };
      res.status(200).json(payload);
    } catch (err: unknown) {
      console.error('[VELTRIX] Response queue query error:', err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: { code: 'STORAGE_QUERY_ERROR', message: 'Failed to read the response queue' },
      };
      res.status(500).json(errorResponse);
    }
  });

  const transition = (
    path: string,
    allowedFrom: ResponseExecution['status'][],
    apply: (execution: ResponseExecution) => Partial<ResponseExecution>
  ) =>
    router.post(path, requireRole('SUPER_ADMIN', 'ORG_ADMIN'), async (req: Request, res: Response) => {
      try {
        const orgId = req.tenantOrgId!;
        const executionId = req.params.executionId as string;
        const execution = await store.getExecutionById(orgId, executionId);

        if (!execution) {
          res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: `Response execution '${executionId}' not found` },
          });
          return;
        }

        if (!allowedFrom.includes(execution.status)) {
          res.status(409).json({
            success: false,
            error: {
              code: 'INVALID_TRANSITION',
              message: `Execution is '${execution.status}'; expected one of [${allowedFrom.join(', ')}].`,
            },
          });
          return;
        }

        const updated = await store.updateExecution(orgId, executionId, apply(execution));
        const action =
          updated?.status === 'ROLLED_BACK'
            ? 'RESPONSE_ROLLED_BACK'
            : updated?.status === 'EXECUTED'
              ? 'RESPONSE_EXECUTED'
              : 'RESPONSE_APPROVED';

        await audit(req, action, {
          executionId,
          incidentId: execution.incidentId,
          actionType: execution.actionType,
          target: execution.target,
          resultingStatus: updated?.status,
          simulated: execution.isSimulated,
        });

        const payload: ApiResponse<ResponseExecution | null> = {
          success: true,
          data: updated,
          meta: { timestamp: new Date().toISOString() },
        };
        res.status(200).json(payload);
      } catch (err: unknown) {
        console.error('[VELTRIX] Response transition error:', err);
        res.status(500).json({
          success: false,
          error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to transition the execution' },
        });
      }
    });

  // Approve + execute (simulated) a pending containment action.
  transition('/:executionId/approve', ['PENDING_APPROVAL', 'APPROVED'], (execution) => ({
    status: 'EXECUTED',
    approvedBy: 'console.approver',
    executedAt: new Date().toISOString(),
    result: {
      success: true,
      message: `${execution.actionType} applied to ${execution.target} (simulated).`,
      details: { simulated: true, approvedVia: 'console' },
    },
  }));

  // Reject a pending action.
  transition('/:executionId/reject', ['PENDING_APPROVAL', 'APPROVED'], () => ({
    status: 'REJECTED',
    result: {
      success: false,
      message: 'Action rejected by approver (simulated).',
      details: { simulated: true, rejectedVia: 'console' },
    },
  }));

  // Roll back an executed action.
  transition('/:executionId/rollback', ['EXECUTED'], () => ({
    status: 'ROLLED_BACK',
    rolledBackAt: new Date().toISOString(),
    result: {
      success: true,
      message: 'Execution rolled back (simulated).',
      details: { simulated: true, rolledBackVia: 'console' },
    },
  }));

  return router;
}
