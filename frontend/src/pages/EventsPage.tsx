import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Activity, Filter, RefreshCw, Search, X } from 'lucide-react';
import type { SecurityEvent, Severity } from '@veltrix/shared';
import { fetchEvents } from '../lib/api/endpoints';
import type { EventQuery } from '../lib/api/endpoints';
import {
  Badge,
  Button,
  Card,
  Drawer,
  EmptyState,
  ErrorState,
  Input,
  KeyValue,
  LoadingPanel,
  PageHeader,
  Select,
  SeverityBadge,
} from '../components/ui/primitives';
import { formatDateTime, formatNumber, shortId, timeAgo, titleCase } from '../lib/format';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const EVENT_TYPES = [
  'web.request.normal',
  'web.attack.sqli',
  'web.attack.xss',
  'web.attack.path_traversal',
  'web.attack.bot',
  'web.attack.auth_tampering',
  'web.scan.detected',
  'auth.login.success',
  'auth.login.failure',
  'auth.credential_stuffing',
  'network.connection.anomaly',
  'recon.account.probe',
];

function MetadataBlock({ event }: { event: SecurityEvent }) {
  const metadata = (event.metadata || {}) as Record<string, unknown>;
  const entries = Object.entries(metadata);
  return (
    <div className="space-y-3">
      <div>
        <div className="vx-label mb-1.5">Normalized metadata</div>
        <div className="rounded-lg border border-veltrix-border bg-veltrix-chrome/70 p-3">
          {entries.length === 0 ? (
            <span className="text-[11px] text-slate-500">No metadata recorded.</span>
          ) : (
            <div className="divide-y divide-veltrix-border/40">
              {entries.map(([key, value]) => (
                <KeyValue
                  key={key}
                  label={key}
                  value={
                    typeof value === 'object' && value !== null ? (
                      <code className="break-all font-mono text-[10px] text-cyan-200/90">
                        {JSON.stringify(value)}
                      </code>
                    ) : (
                      String(value)
                    )
                  }
                />
              ))}
            </div>
          )}
        </div>
      </div>
      <div>
        <div className="vx-label mb-1.5">Raw record</div>
        <pre className="max-h-72 overflow-auto rounded-lg border border-veltrix-border bg-veltrix-chrome/80 p-3 font-mono text-[10px] leading-relaxed text-slate-400 vx-scroll">
          {JSON.stringify(event, null, 2)}
        </pre>
      </div>
    </div>
  );
}

export function EventsPage() {
  const [params, setParams] = useSearchParams();
  const [severity, setSeverity] = useState<string>('');
  const [eventType, setEventType] = useState<string>('');
  const [sourceIp, setSourceIp] = useState<string>(params.get('sourceIp') || '');
  const [limit, setLimit] = useState('100');
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([undefined]);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);

  const cursor = cursorStack[cursorStack.length - 1];

  const query: EventQuery = useMemo(
    () => ({
      limit: Number(limit),
      cursor,
      severity: (severity || undefined) as Severity | undefined,
      eventType: eventType || undefined,
      sourceIp: sourceIp.trim() || undefined,
    }),
    [limit, cursor, severity, eventType, sourceIp]
  );

  const events = useQuery({
    queryKey: ['events', query],
    queryFn: () => fetchEvents(query),
    refetchInterval: 20_000,
  });

  const items = events.data?.data.events || [];
  const nextCursor = events.data?.data.nextCursor;

  const filtersActive = Boolean(severity || eventType || sourceIp);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect"
        title="Telemetry explorer"
        description="Every normalized security event ingested for this tenant, with raw metadata for evidence review."
        actions={
          <>
            <Badge tone="info" dot>
              {formatNumber(events.data?.data.total || 0)} events
            </Badge>
            <Button
              size="sm"
              variant="secondary"
              icon={RefreshCw}
              onClick={() => events.refetch()}
              disabled={events.isFetching}
            >
              {events.isFetching ? 'Loading…' : 'Refresh'}
            </Button>
          </>
        }
      />

      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="space-y-1.5">
            <span className="vx-label">Severity</span>
            <Select value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="">Any severity</option>
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {titleCase(value)}
                </option>
              ))}
            </Select>
          </label>
          <label className="space-y-1.5">
            <span className="vx-label">Event type</span>
            <Select value={eventType} onChange={(event) => setEventType(event.target.value)}>
              <option value="">Any type</option>
              {EVENT_TYPES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </Select>
          </label>
          <label className="min-w-[190px] flex-1 space-y-1.5">
            <span className="vx-label">Source IP</span>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <Input
                value={sourceIp}
                onChange={(event) => setSourceIp(event.target.value)}
                placeholder="198.51.100.23"
                className="pl-9"
              />
            </div>
          </label>
          <label className="space-y-1.5">
            <span className="vx-label">Page size</span>
            <Select value={limit} onChange={(event) => setLimit(event.target.value)}>
              {['50', '100', '250', '500'].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </Select>
          </label>
          {filtersActive ? (
            <Button
              size="sm"
              variant="ghost"
              icon={X}
              onClick={() => {
                setSeverity('');
                setEventType('');
                setSourceIp('');
                setParams({});
              }}
            >
              Clear
            </Button>
          ) : (
            <span className="flex items-center gap-1.5 pb-2 text-[10px] uppercase tracking-wider text-slate-600">
              <Filter className="h-3 w-3" /> no filters
            </span>
          )}
        </div>
      </Card>

      <Card className="overflow-hidden">
        {events.isError ? (
          <ErrorState
            message={events.error instanceof Error ? events.error.message : undefined}
            onRetry={() => events.refetch()}
          />
        ) : events.isLoading ? (
          <LoadingPanel rows={6} />
        ) : items.length === 0 ? (
          <EmptyState
            icon={Activity}
            title="No events match this query"
            description="Adjust the filters, ingest telemetry through an integration, or load the demo dataset from the overview."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="vx-table">
              <thead>
                <tr>
                  <th className="w-28">Severity</th>
                  <th>Event type</th>
                  <th className="w-32">Source IP</th>
                  <th className="w-40">Target</th>
                  <th className="w-32">Observed</th>
                  <th className="w-20">Event ID</th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => {
                  const metadata = (event.metadata || {}) as Record<string, unknown>;
                  return (
                    <tr
                      key={event.eventId}
                      onClick={() => setSelected(event)}
                      className="cursor-pointer"
                    >
                      <td>
                        <SeverityBadge severity={event.severity} />
                      </td>
                      <td>
                        <div className="font-mono text-[11px] text-slate-200">{event.eventType}</div>
                        <div className="text-[10px] text-slate-600">
                          {event.category} · {event.sourceSystem}
                          {event.isSimulated ? ' · simulated' : ''}
                        </div>
                      </td>
                      <td className="font-mono text-[11px] text-cyan-200/90">{event.sourceIp}</td>
                      <td>
                        <div className="truncate font-mono text-[10px] text-slate-400">
                          {String(metadata.requestUri || metadata.domain || event.username || '—')}
                        </div>
                      </td>
                      <td>
                        <div className="text-[11px] text-slate-300">{timeAgo(event.timestamp)}</div>
                        <div className="text-[10px] text-slate-600">
                          {formatDateTime(event.timestamp)}
                        </div>
                      </td>
                      <td className="font-mono text-[10px] text-slate-500">
                        {shortId(event.eventId, 8)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex items-center justify-between border-t border-veltrix-border/70 px-4 py-3">
          <span className="text-[10px] text-slate-500">
            Page {cursorStack.length} · showing {items.length} events
          </span>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={cursorStack.length === 1}
              onClick={() => setCursorStack((stack) => stack.slice(0, -1))}
            >
              Previous
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={!nextCursor}
              onClick={() => nextCursor && setCursorStack((stack) => [...stack, nextCursor])}
            >
              Next
            </Button>
          </div>
        </div>
      </Card>

      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected ? selected.eventType : 'Event'}
        subtitle={selected ? `${selected.eventId} · ${formatDateTime(selected.timestamp)}` : undefined}
      >
        {selected ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border border-veltrix-border bg-veltrix-chrome/50 p-3">
                <div className="vx-label">Severity</div>
                <div className="mt-1">
                  <SeverityBadge severity={selected.severity} />
                </div>
              </div>
              <div className="rounded-lg border border-veltrix-border bg-veltrix-chrome/50 p-3">
                <div className="vx-label">Source</div>
                <div className="mt-1 font-mono text-[12px] text-cyan-200">{selected.sourceIp}</div>
              </div>
            </div>
            <MetadataBlock event={selected} />
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
