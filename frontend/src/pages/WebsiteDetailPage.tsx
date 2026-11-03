import { useParams, Link } from 'react-router-dom';
import { WebsiteAttackMonitoring } from '../components/WebsiteAttackMonitoring';
import { ArrowLeft, Globe } from 'lucide-react';
import { Button } from '../components/ui/primitives';

export function WebsiteDetailPage() {
  const { siteId } = useParams<{ siteId: string }>();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Link to="/websites">
          <Button variant="ghost" size="sm" icon={ArrowLeft}>
            Back to Inventory
          </Button>
        </Link>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg bg-cyan-500/10 text-cyan-400">
            <Globe className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">Asset Security & Attack Monitoring</h1>
            <p className="font-mono text-xs text-slate-400">Target ID: {siteId}</p>
          </div>
        </div>
      </div>

      <WebsiteAttackMonitoring />
    </div>
  );
}
