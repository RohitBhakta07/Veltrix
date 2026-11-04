import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Globe, AlertTriangle, ShieldCheck, Lock, CheckCircle2 } from 'lucide-react';
import { fetchWebsite, fetchSiteRiskSummary, fetchScanAuthorization } from '../lib/api/endpoints';
import { WebsiteAttackMonitoring } from '../components/WebsiteAttackMonitoring';
import { DomainVerificationModal } from '../components/DomainVerificationModal';
import { Card, Badge, Button, LoadingPanel, StatusBadge, RiskBadge } from '../components/ui/primitives';

export function WebsiteDetailPage() {
  const { siteId } = useParams<{ siteId: string }>();
  const [showVerifyModal, setShowVerifyModal] = useState(false);

  const { data: siteRes, isLoading: loadingSite, refetch: refetchSite } = useQuery({
    queryKey: ['website', siteId],
    queryFn: () => fetchWebsite(siteId!),
    enabled: !!siteId,
  });

  const { data: riskRes } = useQuery({
    queryKey: ['website', siteId, 'risk-summary'],
    queryFn: () => fetchSiteRiskSummary(siteId!),
    enabled: !!siteId,
  });

  const { data: scanAuth, refetch: refetchAuth } = useQuery({
    queryKey: ['website', siteId, 'scan-authorization'],
    queryFn: () => fetchScanAuthorization(siteId!),
    enabled: !!siteId,
  });

  const site = siteRes?.site;
  const risk = riskRes?.data;

  if (loadingSite) return <LoadingPanel rows={6} />;

  const isPending = !site || site.status === 'PENDING_VERIFICATION' || site.status === 'GRACE_PERIOD' || site.scanBlocked;

  return (
    <div className="space-y-6">
      {/* Back button */}
      <div className="flex items-center justify-between">
        <Link to="/websites">
          <Button variant="ghost" size="sm" icon={ArrowLeft}>
            Back to Inventory
          </Button>
        </Link>

        {isPending && site && (
          <Button
            variant="primary"
            size="sm"
            icon={ShieldCheck}
            onClick={() => setShowVerifyModal(true)}
          >
            Verify Domain
          </Button>
        )}
      </div>

      {/* Asset Header Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="grid h-12 w-12 place-items-center rounded-xl bg-cyan-500/10 text-cyan-400">
              <Globe className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-white">{site?.name || 'Website Asset'}</h1>
                <StatusBadge status={site?.status || 'VERIFIED'} />
                {site?.riskTier && <Badge tone="neutral">{site.riskTier}</Badge>}
                {isPending ? (
                  <Badge tone="amber">
                    <Lock className="mr-1 h-3 w-3 inline" />
                    Scans Blocked
                  </Badge>
                ) : (
                  <Badge tone="emerald">
                    <CheckCircle2 className="mr-1 h-3 w-3 inline" />
                    Scan Authorized
                  </Badge>
                )}
              </div>
              <p className="font-mono text-xs text-slate-400 mt-0.5">
                {site?.primaryDomain || siteId}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <RiskBadge band={site?.riskTier || risk?.currentRiskBand || 'MEDIUM'} score={risk?.currentRiskScore ?? 45} />
          </div>
        </div>
      </div>

      {/* Grace Period Freeze Alert */}
      {site?.status === 'GRACE_PERIOD' && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-rose-300">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
          <div className="text-xs">
            <span className="font-bold text-rose-200">Domain Verification In Grace Period:</span>{' '}
            Verification was revoked or expired. All active and scheduled scans against this target are frozen. Prove domain ownership within the 7-day grace window to resume scanning.
          </div>
        </div>
      )}

      {/* Risk Factors Breakdown */}
      {risk?.factors && (
        <Card className="p-5 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            Explainable Risk Scoring Breakdown
          </h3>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 font-mono text-xs">
            <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3">
              <span className="text-slate-500 block text-[10px] uppercase">Base Severity</span>
              <span className="text-sm font-bold text-white">{risk.factors.baseSeverity ?? 20}</span>
            </div>
            <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3">
              <span className="text-slate-500 block text-[10px] uppercase">Criticality Mult</span>
              <span className="text-sm font-bold text-cyan-300">
                {risk.factors.assetCriticalityMultiplier ?? 1.0}x
              </span>
            </div>
            <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3">
              <span className="text-slate-500 block text-[10px] uppercase">Threat Mult</span>
              <span className="text-sm font-bold text-amber-300">
                {risk.factors.threatIntelMultiplier ?? 1.0}x
              </span>
            </div>
            <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3">
              <span className="text-slate-500 block text-[10px] uppercase">Sequence Bonus</span>
              <span className="text-sm font-bold text-rose-300">
                +{risk.factors.attackSequenceBonus ?? 0}
              </span>
            </div>
          </div>
        </Card>
      )}

      {/* Attack Monitoring Subsystem */}
      <WebsiteAttackMonitoring />

      {/* Modal */}
      {site && (
        <DomainVerificationModal
          isOpen={showVerifyModal}
          onClose={() => setShowVerifyModal(false)}
          site={site}
          onSuccess={() => {
            refetchSite();
            refetchAuth();
          }}
        />
      )}
    </div>
  );
}
