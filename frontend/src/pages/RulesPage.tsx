import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { SlidersHorizontal, Shield, Play } from 'lucide-react';
import type { DetectionRule } from '@veltrix/shared';
import { fetchRules, testRule, updateRule } from '../lib/api/endpoints';
import { Card, Badge, Button, LoadingPanel, Toggle } from '../components/ui/primitives';

export function RulesPage() {
  const [testPayload, setTestPayload] = useState('{"eventType": "web.attack.sqli", "sourceIp": "198.51.100.42"}');
  const [testResult, setTestResult] = useState<any>(null);
  const [testing, setTesting] = useState(false);
  const queryClient = useQueryClient();

  const { data: rulesRes, isLoading } = useQuery({
    queryKey: ['detection-rules'],
    queryFn: () => fetchRules(),
  });

  const toggleRule = useMutation({
    mutationFn: ({ ruleId, isEnabled }: { ruleId: string; isEnabled: boolean }) =>
      updateRule(ruleId, { isEnabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['detection-rules'] }),
  });

  const rules: DetectionRule[] = rulesRes?.data?.rules || [];

  const handleRunTest = async (ruleId: string) => {
    try {
      setTesting(true);
      const parsed = JSON.parse(testPayload);
      const res = await testRule({ ruleId, sampleEvents: [parsed] });
      setTestResult(res.data);
    } catch (err: any) {
      setTestResult({ error: err.message });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <SlidersHorizontal className="h-5 w-5 text-cyan-400" />
            Detection Rules Catalog
          </h1>
          <p className="text-xs text-slate-400">
            Sigma-inspired threat detection rules, thresholds, and live evaluation testing
          </p>
        </div>
      </div>

      {isLoading ? (
        <LoadingPanel rows={6} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          {rules.map((rule: DetectionRule) => (
            <Card key={rule.ruleId} className="p-4 space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">{rule.ruleId}</span>
                    <Badge tone={rule.severity === 'CRITICAL' ? 'critical' : 'medium'}>{rule.severity}</Badge>
                    <Badge tone={rule.isEnabled ? 'success' : 'neutral'}>
                      {rule.isEnabled ? 'ACTIVE' : 'DISABLED'}
                    </Badge>
                  </div>
                  <h3 className="text-sm font-semibold text-white mt-1">{rule.name}</h3>
                  <p className="text-xs text-slate-400 mt-0.5">{rule.description}</p>
                </div>
                <div className="flex items-center gap-3">
                  <Toggle
                    checked={rule.isEnabled}
                    disabled={toggleRule.isPending}
                    onChange={(checked) =>
                      toggleRule.mutate({ ruleId: rule.ruleId, isEnabled: checked })
                    }
                    label={`Enable ${rule.name}`}
                  />
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={Play}
                    disabled={testing}
                    onClick={() => handleRunTest(rule.ruleId)}
                  >
                    {testing ? 'Testing...' : 'Test Rule'}
                  </Button>
                </div>
              </div>

              <div className="flex items-center gap-4 text-[11px] text-slate-400 font-mono border-t border-slate-800/80 pt-2">
                <span>Threshold: {rule.threshold} events</span>
                <span>Window: {rule.slidingWindowSeconds}s</span>
                {rule.mitreAttack && (
                  <span>MITRE: {rule.mitreAttack.techniqueId} ({rule.mitreAttack.tactic})</span>
                )}
              </div>
            </Card>
          ))}
        </div>

        <div>
          <Card className="p-4 space-y-3 sticky top-20">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400" />
              Live Evaluation Tester
            </h3>
            <p className="text-xs text-slate-400">
              Provide a sample telemetry payload in JSON and click &quot;Test Rule&quot; to test match condition.
            </p>
            <textarea
              className="w-full h-36 font-mono text-xs bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              value={testPayload}
              onChange={(e) => setTestPayload(e.target.value)}
            />
            {testResult && (
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300">
                <div className="font-bold text-cyan-400 mb-1">Result:</div>
                <pre className="overflow-x-auto">{JSON.stringify(testResult, null, 2)}</pre>
              </div>
            )}
          </Card>
        </div>
      </div>
      )}
    </div>
  );
}
