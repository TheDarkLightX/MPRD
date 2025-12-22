import { MOCK_DATA_REQUESTED, USE_MOCK_DATA } from '../../config';

export function ModeBanner() {
  if (MOCK_DATA_REQUESTED && import.meta.env.PROD) {
    return (
      <div className="mx-6 mt-3 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
        Mock mode is disabled in production builds. Fix `VITE_USE_MOCK_DATA`.
      </div>
    );
  }
  if (!USE_MOCK_DATA) return null;

  return (
    <div className="mx-6 mt-3 rounded-lg border border-degraded/30 bg-degraded/10 px-3 py-2 text-sm text-degraded">
      Operator UI is running in mock-data mode (`VITE_USE_MOCK_DATA=true`). No backend data is being displayed.
    </div>
  );
}
