import type { RouteObject } from 'react-router-dom';
import { createBrowserRouter, createMemoryRouter } from 'react-router-dom';
import { AppShell, ShellErrorFallback } from './AppShell';
import { RequireAuth } from '../features/auth/AuthProvider';

import { OverviewPage } from '../pages/OverviewPage';
import { EventsPage } from '../pages/EventsPage';
import { DetectionsPage } from '../pages/DetectionsPage';
import { RulesPage } from '../pages/RulesPage';
import { WebsitesPage } from '../pages/WebsitesPage';
import { WebsiteDetailPage } from '../pages/WebsiteDetailPage';
import { IntegrationsPage } from '../pages/IntegrationsPage';
import { ScansPage } from '../pages/ScansPage';
import { FindingsPage } from '../pages/FindingsPage';
import { IncidentsPage } from '../pages/IncidentsPage';
import { IncidentDetailPage } from '../pages/IncidentDetailPage';
import { ResponsePage } from '../pages/ResponsePage';
import { AuditPage } from '../pages/AuditPage';
import { IntelPage } from '../pages/IntelPage';
import { SettingsPage } from '../pages/SettingsPage';
import { LoginPage } from '../pages/LoginPage';

export const appRoutes: RouteObject[] = [
  {
    path: '/',
    element: (
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    ),
    errorElement: <ShellErrorFallback />,
    children: [
      { path: '', element: <OverviewPage /> },
      { path: 'events', element: <EventsPage /> },
      { path: 'detections', element: <DetectionsPage /> },
      { path: 'rules', element: <RulesPage /> },
      { path: 'websites', element: <WebsitesPage /> },
      { path: 'websites/:siteId', element: <WebsiteDetailPage /> },
      { path: 'integrations', element: <IntegrationsPage /> },
      { path: 'scans', element: <ScansPage /> },
      { path: 'findings', element: <FindingsPage /> },
      { path: 'incidents', element: <IncidentsPage /> },
      { path: 'incidents/:incidentId', element: <IncidentDetailPage /> },
      { path: 'response', element: <ResponsePage /> },
      { path: 'audit', element: <AuditPage /> },
      { path: 'intel', element: <IntelPage /> },
      { path: 'settings', element: <SettingsPage /> },
    ],
  },
  {
    path: '/login',
    element: <LoginPage />,
  },
];

export const routes = appRoutes;

export const router =
  typeof document !== 'undefined'
    ? createBrowserRouter(appRoutes)
    : createMemoryRouter(appRoutes);
