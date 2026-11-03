import {
  useEffect,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
} from 'react';
import { createPortal } from 'react-dom';
import clsx, { type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
  Check,
  ChevronDown,
  Copy,
  Inbox,
  RefreshCw,
  ShieldAlert,
  X,
  type LucideIcon,
} from 'lucide-react';
import type { Severity } from '@veltrix/shared';
import {
  confidenceLabel,
  confidenceTone,
  riskTone,
  severityTone,
  titleCase,
  type Tone,
} from '../../lib/format';

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

// --- Button -----------------------------------------------------------------

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
type ButtonSize = 'sm' | 'md' | 'lg';

const buttonVariants: Record<ButtonVariant, string> = {
  primary: 'vx-button-primary',
  secondary: 'vx-button-secondary',
  ghost: 'vx-button-ghost',
  danger: 'vx-button-danger',
};

const buttonSizes: Record<ButtonSize, string> = {
  sm: 'px-2.5 py-1.5 text-xs',
  md: '',
  lg: 'px-5 py-2.5 text-sm',
};

export function Button({
  variant = 'secondary',
  size = 'md',
  icon: Icon,
  className,
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: LucideIcon;
}) {
  return (
    <button
      className={cn(buttonVariants[variant], buttonSizes[size], className)}
      {...props}
    >
      {Icon ? <Icon className={size === 'sm' ? 'h-3.5 w-3.5' : 'h-4 w-4'} /> : null}
      {children}
    </button>
  );
}

// --- Badges -----------------------------------------------------------------

const toneStyles: Record<Tone, string> = {
  critical: 'border-rose-500/35 bg-rose-500/10 text-rose-300',
  high: 'border-orange-500/35 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-400/35 bg-amber-400/10 text-amber-300',
  low: 'border-sky-500/35 bg-sky-500/10 text-sky-300',
  success: 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300',
  neutral: 'border-slate-600/50 bg-slate-700/20 text-slate-300',
  info: 'border-cyan-500/35 bg-cyan-500/10 text-cyan-300',
};

const dotStyles: Record<Tone, string> = {
  critical: 'bg-rose-400',
  high: 'bg-orange-400',
  medium: 'bg-amber-300',
  low: 'bg-sky-400',
  success: 'bg-emerald-400',
  neutral: 'bg-slate-400',
  info: 'bg-cyan-300',
};

export function Badge({
  tone = 'neutral',
  dot = false,
  className,
  children,
}: {
  tone?: Tone;
  dot?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <span className={cn('vx-chip', toneStyles[tone], className)}>
      {dot ? <span className={cn('h-1.5 w-1.5 rounded-full', dotStyles[tone])} /> : null}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity?: Severity | string }) {
  return (
    <Badge tone={severityTone(severity)} dot>
      {severity || 'UNKNOWN'}
    </Badge>
  );
}

export function RiskBadge({ band, score }: { band?: string; score?: number }) {
  return (
    <Badge tone={riskTone(band)} dot>
      {band || 'LOW'}
      {typeof score === 'number' ? <span className="font-mono opacity-70">{score}</span> : null}
    </Badge>
  );
}

export function ConfidenceBadge({ confidence }: { confidence?: string | number }) {
  return <Badge tone={confidenceTone(confidence)}>{confidenceLabel(confidence)}</Badge>;
}

export function StatusBadge({ status }: { status?: string }) {
  const normalized = status || 'UNKNOWN';
  const success = [
    'VERIFIED',
    'HEALTHY',
    'EXECUTED',
    'RESOLVED',
    'APPROVED',
    'CONFIRMED',
    'ACTIVE',
  ];
  const medium = [
    'PENDING_VERIFICATION',
    'GRACE_PERIOD',
    'INVESTIGATING',
    'PENDING_APPROVAL',
    'IN_REMEDIATION',
    'DEGRADED',
  ];
  const danger = ['EXPIRED', 'REVOKED', 'SUSPENDED', 'FAILED', 'BLOCKED', 'ROLLED_BACK'];
  const tone: Tone = success.includes(normalized)
    ? 'success'
    : medium.includes(normalized)
      ? 'medium'
      : danger.includes(normalized)
        ? 'critical'
        : normalized === 'NEW'
          ? 'info'
          : normalized === 'CONTAINED'
            ? 'low'
            : 'neutral';
  return (
    <Badge tone={tone} dot>
      {titleCase(normalized)}
    </Badge>
  );
}

// --- Surfaces ---------------------------------------------------------------

export function Card({
  className,
  children,
  interactive = false,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { interactive?: boolean }) {
  return (
    <div
      className={cn(
        'vx-card',
        interactive && 'transition-colors hover:border-slate-600/80',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4 border-b border-veltrix-border/70 pb-5 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0 space-y-1.5">
        {eyebrow ? <div className="vx-label text-veltrix-cyan/80">{eyebrow}</div> : null}
        <h1 className="truncate text-2xl font-bold tracking-tight text-white">{title}</h1>
        {description ? (
          <p className="max-w-3xl text-sm leading-relaxed text-slate-400">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function SectionHeader({
  title,
  description,
  action,
  className,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex items-start justify-between gap-4', className)}>
      <div>
        <h2 className="text-sm font-semibold tracking-wide text-slate-100">{title}</h2>
        {description ? <p className="mt-0.5 text-xs text-slate-500">{description}</p> : null}
      </div>
      {action}
    </div>
  );
}

// --- KPI --------------------------------------------------------------------

export function KpiTile({
  label,
  value,
  hint,
  icon: Icon,
  tone = 'info',
  trend,
  onClick,
}: {
  label: string;
  value: string | number;
  hint?: string;
  icon?: LucideIcon;
  tone?: Tone;
  trend?: string;
  onClick?: () => void;
}) {
  const accent: Record<Tone, string> = {
    critical: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
    high: 'text-orange-300 bg-orange-500/10 border-orange-500/20',
    medium: 'text-amber-300 bg-amber-400/10 border-amber-400/20',
    low: 'text-sky-300 bg-sky-500/10 border-sky-500/20',
    success: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20',
    neutral: 'text-slate-300 bg-slate-500/10 border-slate-500/20',
    info: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/20',
  };

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!onClick}
      className={cn(
        'vx-card group relative overflow-hidden p-4 text-left',
        onClick && 'hover:border-cyan-500/30 hover:shadow-glow'
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="vx-label">{label}</div>
          <div className="mt-2 text-2xl font-bold tabular-nums tracking-tight text-white">
            {value}
          </div>
        </div>
        {Icon ? (
          <span className={cn('rounded-lg border p-2', accent[tone])}>
            <Icon className="h-4 w-4" />
          </span>
        ) : null}
      </div>
      <div className="mt-2 flex items-center gap-2 text-[11px] text-slate-500">
        {trend ? <span className={cn('font-medium', accent[tone].split(' ')[0])}>{trend}</span> : null}
        {hint ? <span className="truncate">{hint}</span> : null}
      </div>
    </button>
  );
}

// --- States -----------------------------------------------------------------

export function EmptyState({
  title,
  description,
  action,
  icon: Icon = Inbox,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  icon?: LucideIcon;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="rounded-2xl border border-veltrix-border bg-veltrix-surface/70 p-4 text-slate-500">
        <Icon className="h-7 w-7" />
      </div>
      <div>
        <div className="text-sm font-semibold text-slate-200">{title}</div>
        {description ? (
          <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-slate-500">
            {description}
          </p>
        ) : null}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({
  title = 'Unable to load this view',
  message,
  onRetry,
}: {
  title?: string;
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-4 text-rose-300">
        <ShieldAlert className="h-7 w-7" />
      </div>
      <div>
        <div className="text-sm font-semibold text-slate-200">{title}</div>
        {message ? <p className="mt-1 max-w-md text-xs text-slate-500">{message}</p> : null}
      </div>
      {onRetry ? (
        <Button variant="secondary" size="sm" icon={RefreshCw} onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('vx-skeleton h-4 w-full', className)} />;
}

export function LoadingPanel({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3 p-5">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="flex items-center gap-4">
          <Skeleton className="h-9 w-9 rounded-lg" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-3 w-1/3" />
            <Skeleton className="h-3 w-2/3" />
          </div>
        </div>
      ))}
    </div>
  );
}

// --- Overlays ---------------------------------------------------------------

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  const widths = { sm: 'max-w-md', md: 'max-w-xl', lg: 'max-w-3xl', xl: 'max-w-5xl' };

  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-start justify-center overflow-y-auto bg-black/70 p-4 backdrop-blur-sm sm:p-8">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn(
          'my-auto w-full overflow-hidden rounded-2xl border border-veltrix-border bg-veltrix-card shadow-card animate-fade-up',
          widths[size]
        )}
      >
        <div className="flex items-start justify-between gap-4 border-b border-veltrix-border px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-white">{title}</h2>
            {description ? <p className="mt-1 text-xs text-slate-400">{description}</p> : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-white/5 hover:text-white"
            aria-label="Close dialog"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto p-5 vx-scroll">{children}</div>
        {footer ? (
          <div className="flex items-center justify-end gap-2 border-t border-veltrix-border px-5 py-3">
            {footer}
          </div>
        ) : null}
      </div>
    </div>,
    document.body
  );
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[100] flex justify-end bg-black/60 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="flex h-full w-full max-w-2xl flex-col border-l border-veltrix-border bg-veltrix-card shadow-card"
      >
        <div className="flex items-start justify-between gap-4 border-b border-veltrix-border px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-white">{title}</h2>
            {subtitle ? <p className="mt-1 text-xs text-slate-400">{subtitle}</p> : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-white/5 hover:text-white"
            aria-label="Close drawer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5 vx-scroll">{children}</div>
        {footer ? (
          <div className="border-t border-veltrix-border px-5 py-3">{footer}</div>
        ) : null}
      </div>
    </div>,
    document.body
  );
}

// --- Controls ---------------------------------------------------------------

export function Tabs({
  tabs,
  value,
  onChange,
}: {
  tabs: Array<{ id: string; label: string; count?: number }>;
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1 rounded-lg border border-veltrix-border bg-veltrix-surface/60 p-1">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={cn(
            'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition',
            value === tab.id
              ? 'bg-cyan-500/10 text-cyan-300 shadow-[inset_0_0_0_1px_rgba(0,242,254,0.25)]'
              : 'text-slate-400 hover:text-slate-200'
          )}
        >
          {tab.label}
          {typeof tab.count === 'number' ? (
            <span className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
              {tab.count}
            </span>
          ) : null}
        </button>
      ))}
    </div>
  );
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn('vx-input', className)} {...props} />;
}

export function Select({
  className,
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <div className="relative">
      <select className={cn('vx-input appearance-none pr-8', className)} {...props}>
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
    </div>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative h-5 w-9 rounded-full border transition disabled:opacity-50',
        checked
          ? 'border-cyan-400/50 bg-cyan-500/30'
          : 'border-slate-600 bg-slate-800'
      )}
    >
      <span
        className={cn(
          'absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all',
          checked ? 'left-[18px] bg-cyan-300' : 'left-0.5 bg-slate-400'
        )}
      />
    </button>
  );
}

export function ProgressBar({
  value,
  tone = 'info',
  className,
}: {
  value: number;
  tone?: Tone;
  className?: string;
}) {
  const colors: Record<Tone, string> = {
    critical: 'bg-rose-400',
    high: 'bg-orange-400',
    medium: 'bg-amber-300',
    low: 'bg-sky-400',
    success: 'bg-emerald-400',
    neutral: 'bg-slate-400',
    info: 'bg-cyan-400',
  };
  return (
    <div className={cn('h-1.5 w-full overflow-hidden rounded-full bg-white/5', className)}>
      <div
        className={cn('h-full rounded-full transition-all duration-500', colors[tone])}
        style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
      />
    </div>
  );
}

export function CopyField({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard can be blocked; the value remains selectable.
    }
  };
  return (
    <div className="space-y-1">
      {label ? <div className="vx-label">{label}</div> : null}
      <div className="flex items-center gap-2 rounded-lg border border-veltrix-border bg-veltrix-chrome/70 px-3 py-2">
        <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-cyan-200">{value}</code>
        <button
          type="button"
          onClick={copy}
          className="rounded p-1 text-slate-400 transition hover:bg-white/5 hover:text-white"
          aria-label="Copy value"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      </div>
    </div>
  );
}

export function KeyValue({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-veltrix-border/50 py-2 last:border-0">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="text-right text-xs font-medium text-slate-200">{value}</span>
    </div>
  );
}
