export function computeBackendIndicator(args: {
  healthIsError: boolean;
  healthStatus?: number;
  statusIsNetworkError: boolean;
  healthIsNetworkError: boolean;
  statusErrorStatus?: number;
  statusIsError: boolean;
  statusIsFetching: boolean;
}): { dotClass: string; title: string; label: string } {
  const {
    healthIsError,
    healthStatus,
    statusIsNetworkError,
    healthIsNetworkError,
    statusErrorStatus,
    statusIsError,
    statusIsFetching,
  } = args;

  if (healthIsError) {
    const wrongBase = healthStatus === 404;
    return {
      dotClass: 'bg-critical',
      title: wrongBase
        ? 'Health endpoint not found (check API base URL)'
        : 'Backend unreachable',
      label: wrongBase ? 'Wrong base URL' : 'Backend offline',
    };
  }

  if (healthIsNetworkError || statusIsNetworkError) {
    return { dotClass: 'bg-critical', title: 'Backend unreachable', label: 'Backend offline' };
  }

  if (statusErrorStatus === 401) {
    return { dotClass: 'bg-degraded', title: 'Authentication required', label: 'Auth required' };
  }

  if (statusIsError) {
    return { dotClass: 'bg-critical', title: 'Backend unreachable', label: 'API error' };
  }

  if (statusIsFetching) {
    return { dotClass: 'bg-degraded', title: 'Refreshing status…', label: 'Refreshing…' };
  }

  return { dotClass: 'bg-healthy', title: 'Backend connected', label: 'Backend connected' };
}

export function computeBackendBannerFlags(args: {
  healthIsError: boolean;
  healthIsSuccess: boolean;
  healthStatus?: number;
  healthIsNetworkError: boolean;
  statusIsNetworkError: boolean;
  statusErrorStatus?: number;
}): { showWrongBaseUrl: boolean; showOffline: boolean; showAuthRequired: boolean } {
  const {
    healthIsError,
    healthIsSuccess,
    healthStatus,
    healthIsNetworkError,
    statusIsNetworkError,
    statusErrorStatus,
  } = args;

  const showWrongBaseUrl = healthIsError && healthStatus === 404;
  const showOffline = !showWrongBaseUrl && (healthIsNetworkError || statusIsNetworkError);
  const showAuthRequired =
    !showWrongBaseUrl && !showOffline && healthIsSuccess && statusErrorStatus === 401;

  return { showWrongBaseUrl, showOffline, showAuthRequired };
}

