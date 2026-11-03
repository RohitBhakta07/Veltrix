import {
  Activity,
  Bug,
  Crosshair,
  Globe2,
  LayoutDashboard,
  Plug,
  Radar,
  ScanLine,
  ScrollText,
  Settings,
  ShieldCheck,
  Siren,
  SlidersHorizontal,
  type LucideIcon,
} from 'lucide-react';

export interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
  description: string;
  shortcut?: string;
  badge?: 'incidents' | 'scans';
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Command',
    items: [
      {
        path: '/',
        label: 'Overview',
        icon: LayoutDashboard,
        description: 'Executive posture, telemetry and risk',
        shortcut: 'g o',
      },
      {
        path: '/incidents',
        label: 'Incidents',
        icon: Siren,
        description: 'Triage correlated attacks',
        shortcut: 'g i',
        badge: 'incidents',
      },
    ],
  },
  {
    label: 'Detect',
    items: [
      {
        path: '/events',
        label: 'Events',
        icon: Activity,
        description: 'Raw security telemetry explorer',
        shortcut: 'g e',
      },
      {
        path: '/detections',
        label: 'Detections',
        icon: Radar,
        description: 'Web attack detections and confidence',
        shortcut: 'g d',
      },
      {
        path: '/rules',
        label: 'Rules',
        icon: SlidersHorizontal,
        description: 'Tune Sigma-inspired detection rules',
      },
      {
        path: '/intel',
        label: 'Threat intel',
        icon: Crosshair,
        description: 'IOC catalogue and IP dossiers',
      },
    ],
  },
  {
    label: 'Assess',
    items: [
      {
        path: '/websites',
        label: 'Websites',
        icon: Globe2,
        description: 'Verified assets and ownership',
      },
      {
        path: '/integrations',
        label: 'Integrations',
        icon: Plug,
        description: 'Telemetry agents and API keys',
      },
      {
        path: '/scans',
        label: 'Scans',
        icon: ScanLine,
        description: 'Authorized vulnerability assessments',
        badge: 'scans',
      },
      {
        path: '/findings',
        label: 'Findings',
        icon: Bug,
        description: 'Vulnerability lifecycle and evidence',
      },
    ],
  },
  {
    label: 'Respond',
    items: [
      {
        path: '/response',
        label: 'Response queue',
        icon: ShieldCheck,
        description: 'Approval-gated defensive actions',
      },
      {
        path: '/audit',
        label: 'Audit ledger',
        icon: ScrollText,
        description: 'SHA-256 hash-chain verification',
      },
    ],
  },
  {
    label: 'Platform',
    items: [
      {
        path: '/settings',
        label: 'Settings',
        icon: Settings,
        description: 'Tenant, team and demo data',
      },
    ],
  },
];

export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((group) => group.items);

export function findNavItem(pathname: string): NavItem | undefined {
  if (pathname === '/') return NAV_ITEMS[0];
  return NAV_ITEMS.find((item) => item.path !== '/' && pathname.startsWith(item.path));
}
