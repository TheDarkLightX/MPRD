const STORAGE_API_BASE_URL = 'mprd_operator_api_base_url';
const STORAGE_API_KEY = 'mprd_operator_api_key';

export const DEFAULT_API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';

export const DEFAULT_API_KEY = import.meta.env.VITE_API_KEY || '';

export function normalizeApiBaseUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return DEFAULT_API_BASE_URL;
  // Strip trailing slashes to avoid accidental double-slashes in fetch paths.
  return trimmed.replace(/\/+$/, '');
}

function readLocalStorage(key: string): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function getApiBaseUrl(): string {
  const v = readLocalStorage(STORAGE_API_BASE_URL);
  return v ? normalizeApiBaseUrl(v) : DEFAULT_API_BASE_URL;
}

export function getApiKey(): string {
  const v = readLocalStorage(STORAGE_API_KEY);
  return (v && v.trim()) ? v.trim() : DEFAULT_API_KEY;
}

export function setApiConfig(next: { apiBaseUrl: string; apiKey: string }) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_API_BASE_URL, normalizeApiBaseUrl(next.apiBaseUrl));
  window.localStorage.setItem(STORAGE_API_KEY, next.apiKey);
}

export function clearApiConfig() {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(STORAGE_API_BASE_URL);
  window.localStorage.removeItem(STORAGE_API_KEY);
}

export const MOCK_DATA_REQUESTED =
  (import.meta.env.VITE_USE_MOCK_DATA || '').toLowerCase() === 'true';

// Production safety: never show fake data in a production build.
// Production safety: never show fake data in a production build.
export const USE_MOCK_DATA =
  MOCK_DATA_REQUESTED && !import.meta.env.PROD;
