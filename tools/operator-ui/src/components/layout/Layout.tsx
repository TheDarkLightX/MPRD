/**
 * Main application layout with sidebar navigation
 */

import { Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
    LayoutDashboard,
    FileCheck,
    FileCode,
    Bell,
    Settings,
    Activity,
    Shield
} from 'lucide-react';
import { ModeBanner } from './ModeBanner';
import { useOperatorAlerts } from '../../hooks';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../api/client';
import { ApiError } from '../../api/client';
import { USE_MOCK_DATA } from '../../config';
import { computeBackendBannerFlags, computeBackendIndicator } from '../../algorithms/backendConnectivity';
import { ThemeToggle } from '../ui';

const navItems = [
    { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/decisions', icon: FileCheck, label: 'Decisions' },
    { path: '/policies', icon: FileCode, label: 'Policies' },
    { path: '/security', icon: Shield, label: 'Security' },
    { path: '/settings', icon: Settings, label: 'Settings' },
];

export function Layout() {
    const location = useLocation();
    const navigate = useNavigate();
    const { alerts } = useOperatorAlerts();
    const unresolvedAlerts = alerts.filter(a => !a.acknowledged).length;
    const healthQuery = useQuery({
        queryKey: ['health'],
        queryFn: () => apiClient.getHealth(),
        enabled: !USE_MOCK_DATA,
        refetchInterval: 30_000,
    });
    const statusQuery = useQuery({
        queryKey: ['status'],
        queryFn: () => apiClient.getStatus(),
        enabled: !USE_MOCK_DATA,
        refetchInterval: 5000,
    });
    const statusError = statusQuery.error instanceof ApiError ? statusQuery.error : null;
    const healthError = healthQuery.error instanceof ApiError ? healthQuery.error : null;
    const healthIsNetworkError = healthError?.status === 0;
    const statusIsNetworkError = statusError?.status === 0;
    const { showWrongBaseUrl, showOffline, showAuthRequired } = computeBackendBannerFlags({
        healthIsError: healthQuery.isError,
        healthIsSuccess: healthQuery.isSuccess,
        healthStatus: healthError?.status,
        healthIsNetworkError,
        statusIsNetworkError,
        statusErrorStatus: statusError?.status,
    });
    const indicator = computeBackendIndicator({
        healthIsError: healthQuery.isError,
        healthStatus: healthError?.status,
        healthIsNetworkError,
        statusIsNetworkError,
        statusErrorStatus: statusError?.status,
        statusIsError: statusQuery.isError,
        statusIsFetching: statusQuery.isFetching,
    });

    return (
        <div className="flex h-screen bg-dark-950">
            {/* Sidebar */}
            <aside className="w-64 bg-dark-900 border-r border-dark-800 flex flex-col">
                {/* Logo */}
                <div className="h-16 flex items-center px-6 border-b border-dark-800">
                    <Activity className="w-8 h-8 text-accent-500" />
                    <span className="ml-3 text-xl font-semibold text-gradient">
                        MPRD
                    </span>
                    <span className="ml-2 text-sm text-dark-400">Operator</span>
                </div>

                {/* Navigation */}
                <nav className="flex-1 overflow-y-auto py-4">
                    <ul className="space-y-1 px-3">
                        {navItems.map((item) => {
                            const isActive =
                                item.path === '/'
                                    ? location.pathname === '/'
                                    : location.pathname.startsWith(item.path);

                            return (
                                <li key={item.path}>
                                    <NavLink
                                        to={item.path}
                                        className={`
                      flex items-center px-3 py-2.5 rounded-lg text-sm font-medium
                      transition-all duration-200
                      ${isActive
                                                ? 'bg-accent-500/10 text-accent-400 border-l-2 border-accent-500'
                                                : 'text-dark-400 hover:text-gray-200 hover:bg-dark-800'
                                            }
                    `}
                                    >
                                        <item.icon className="w-5 h-5 mr-3" />
                                        {item.label}
                                    </NavLink>
                                </li>
                            );
                        })}
                    </ul>
                </nav>

                {/* Footer */}
                <div className="px-4 py-3 border-t border-dark-800 text-xs text-dark-500">
                    MPRD v{import.meta.env.VITE_VERSION || '0.1.0'}
                </div>
            </aside>

            {/* Main content */}
            <div className="flex-1 flex flex-col overflow-hidden">
                {/* Header */}
                <header className="h-16 bg-dark-900/50 border-b border-dark-800 flex items-center justify-between px-6">
                    <div className="flex items-center gap-3 text-sm">
                        {!USE_MOCK_DATA && (
                            <div className="flex items-center gap-2 text-dark-400">
                                <span
                                    className={`w-2 h-2 rounded-full ${indicator.dotClass}`}
                                    aria-label="Backend status"
                                    title={indicator.title}
                                />
                                <span className="hidden sm:inline">
                                    {indicator.label}
                                </span>
                            </div>
                        )}
                    </div>

                    <div className="flex items-center space-x-2">
                        {/* Theme toggle */}
                        <ThemeToggle />

                        {/* Alert button */}
                        <button
                            className="relative p-2 rounded-lg hover:bg-dark-800 text-dark-400 hover:text-gray-200 transition-colors"
                            onClick={() => navigate('/security')}
                            aria-label="View security alerts"
                        >
                            <Bell className="w-5 h-5" />
                            {unresolvedAlerts > 0 && (
                                <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 bg-critical rounded-full text-[10px] leading-4 text-dark-950 font-semibold text-center">
                                    {unresolvedAlerts > 99 ? '99+' : unresolvedAlerts}
                                </span>
                            )}
                        </button>

                        {/* User menu placeholder */}
                        <div className="w-8 h-8 rounded-full bg-dark-700 flex items-center justify-center text-sm font-medium text-dark-300">
                            OP
                        </div>
                    </div>
                </header>

                {!USE_MOCK_DATA && (showWrongBaseUrl || showOffline || showAuthRequired) && (
                    <div className="px-6 py-2 border-b border-dark-800 bg-dark-900/30 text-xs">
                        {showWrongBaseUrl ? (
                            <div className="flex flex-wrap items-center gap-2 text-critical">
                                <span>Health endpoint not found. Check the API base URL.</span>
                                <button className="btn-ghost" onClick={() => navigate('/settings')}>
                                    Open Settings
                                </button>
                            </div>
                        ) : showOffline ? (
                            <div className="flex flex-wrap items-center gap-2 text-critical">
                                <span>Backend unreachable. Check host/port and that `mprd serve` is running.</span>
                                <button className="btn-ghost" onClick={() => navigate('/settings')}>
                                    Open Settings
                                </button>
                                <button className="btn-ghost" onClick={() => { void healthQuery.refetch(); void statusQuery.refetch(); }}>
                                    Retry
                                </button>
                            </div>
                        ) : (
                            <div className="flex flex-wrap items-center gap-2 text-degraded">
                                <span>API key required. Configure it in Settings.</span>
                                <button className="btn-ghost" onClick={() => navigate('/settings')}>
                                    Open Settings
                                </button>
                            </div>
                        )}
                    </div>
                )}

                <ModeBanner />

                {/* Page content */}
                <main className="flex-1 overflow-y-auto p-6">
                    <Outlet />
                </main>
            </div>
        </div>
    );
}
