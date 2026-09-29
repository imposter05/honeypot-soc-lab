// Hiten | 2026
// main.tsx

import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-mono/400.css'
import './styles.scss'

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, Link, RouterProvider } from 'react-router-dom'
import { Toaster } from 'sonner'
import { startLive } from './core/live'
import { Shell } from './core/shell'
import { DetectionPage, DetectionsPage } from './pages/detections'
import { EventPage, EventsPage } from './pages/events'
import { IncidentsPage } from './pages/incidents'
import { IncidentPage } from './pages/incidents/detail'
import { LabPage } from './pages/lab'
import { ObservablesPage } from './pages/observables'
import { OverviewPage } from './pages/overview'
import { SessionPage, SessionsPage } from './pages/sessions'
import { SettingsPage } from './pages/settings'
import { SourcePage, SourcesPage } from './pages/sources'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 5000, retry: 1, refetchOnWindowFocus: true },
  },
})

function NotFound() {
  return (
    <div className="empty">
      <p>
        There is no page here. <Link to="/">Go to the overview</Link>.
      </p>
    </div>
  )
}

const router = createBrowserRouter([
  {
    path: '/',
    element: <Shell />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: 'incidents', element: <IncidentsPage /> },
      { path: 'incidents/:id', element: <IncidentPage /> },
      { path: 'events', element: <EventsPage /> },
      { path: 'events/:id', element: <EventPage /> },
      { path: 'sessions', element: <SessionsPage /> },
      { path: 'sessions/:id', element: <SessionPage /> },
      { path: 'detections', element: <DetectionsPage /> },
      { path: 'detections/:id', element: <DetectionPage /> },
      { path: 'observables', element: <ObservablesPage /> },
      { path: 'sources', element: <SourcesPage /> },
      { path: 'sources/:id', element: <SourcePage /> },
      { path: 'lab', element: <LabPage /> },
      { path: 'settings', element: <SettingsPage /> },
      { path: '*', element: <NotFound /> },
    ],
  },
])

startLive()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <Toaster position="bottom-right" richColors closeButton />
    </QueryClientProvider>
  </StrictMode>
)
