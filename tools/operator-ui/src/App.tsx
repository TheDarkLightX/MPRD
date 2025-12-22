/**
 * MPRD Operator Console - Main App
 * 
 * Root application component with routing and providers.
 * 
 * @performance Code-splitting: pages lazy-loaded on demand
 * @keyboard Press ? to see available keyboard shortcuts
 */

import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/layout';
import { DashboardPage } from './pages';
import { LiveEventsProvider } from './context/LiveEventsContext';
import { AutopilotProvider } from './context/AutopilotContext';
import { ThemeProvider } from './context/ThemeContext';
import { KeyboardShortcutsProvider } from './context/KeyboardShortcutsContext';
import { ErrorBoundary, CardSkeleton } from './components/ui';

// Lazy-loaded pages for code splitting
// Dashboard is eagerly loaded (most common entry point)
const DecisionsPage = lazy(() => import('./pages/Decisions').then(m => ({ default: m.DecisionsPage })));
const PoliciesPage = lazy(() => import('./pages/Policies').then(m => ({ default: m.PoliciesPage })));
const SecurityPage = lazy(() => import('./pages/Security').then(m => ({ default: m.SecurityPage })));
const SettingsPage = lazy(() => import('./pages/Settings').then(m => ({ default: m.SettingsPage })));

// Loading fallback for lazy-loaded pages
function PageSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="h-8 w-48 bg-dark-800 rounded-lg" />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <CardSkeleton />
        <CardSkeleton />
        <CardSkeleton />
      </div>
    </div>
  );
}

// Create a React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5000,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <QueryClientProvider client={queryClient}>
          <LiveEventsProvider>
            <AutopilotProvider>
              <BrowserRouter>
                <KeyboardShortcutsProvider>
                  <Routes>
                    <Route element={<Layout />}>
                      <Route path="/" element={<DashboardPage />} />
                      <Route path="/decisions" element={
                        <Suspense fallback={<PageSkeleton />}>
                          <DecisionsPage />
                        </Suspense>
                      } />
                      <Route path="/policies" element={
                        <Suspense fallback={<PageSkeleton />}>
                          <PoliciesPage />
                        </Suspense>
                      } />
                      <Route path="/security" element={
                        <Suspense fallback={<PageSkeleton />}>
                          <SecurityPage />
                        </Suspense>
                      } />
                      <Route path="/settings" element={
                        <Suspense fallback={<PageSkeleton />}>
                          <SettingsPage />
                        </Suspense>
                      } />
                    </Route>
                  </Routes>
                </KeyboardShortcutsProvider>
              </BrowserRouter>
            </AutopilotProvider>
          </LiveEventsProvider>
        </QueryClientProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;

