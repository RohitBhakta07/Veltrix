import type { AuthSession, AuthUser, UserRole } from '@veltrix/shared';

const ACCESS_TOKEN_KEY = 'veltrix.accessToken';
const REFRESH_TOKEN_KEY = 'veltrix.refreshToken';
const USER_KEY = 'veltrix.user';

type SessionListener = () => void;
const listeners = new Set<SessionListener>();

let memoryAccessToken: string | null = null;
let memoryRefreshToken: string | null = null;
let memoryUser: AuthUser | null = null;

function safeStorage(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}

function readValue(key: string): string | null {
  try {
    return safeStorage()?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

export function getAccessToken(): string | null {
  return readValue(ACCESS_TOKEN_KEY) ?? memoryAccessToken;
}

export function getRefreshToken(): string | null {
  return readValue(REFRESH_TOKEN_KEY) ?? memoryRefreshToken;
}

export function getStoredUser(): AuthUser | null {
  const raw = readValue(USER_KEY);
  if (raw) {
    try {
      return JSON.parse(raw) as AuthUser;
    } catch {
      // ignore
    }
  }
  return memoryUser;
}

export function setSession(session: AuthSession): void {
  memoryAccessToken = session.tokens.accessToken;
  memoryRefreshToken = session.tokens.refreshToken || null;
  memoryUser = session.user;

  try {
    const storage = safeStorage();
    storage?.setItem(ACCESS_TOKEN_KEY, session.tokens.accessToken);
    if (session.tokens.refreshToken) {
      storage?.setItem(REFRESH_TOKEN_KEY, session.tokens.refreshToken);
    }
    storage?.setItem(USER_KEY, JSON.stringify(session.user));
  } catch {
    // Storage can be unavailable in private mode; the in-memory copy still works for this tab.
  }
  notify();
}

export function updateTokens(accessToken: string, refreshToken?: string): void {
  memoryAccessToken = accessToken;
  if (refreshToken) memoryRefreshToken = refreshToken;

  try {
    const storage = safeStorage();
    storage?.setItem(ACCESS_TOKEN_KEY, accessToken);
    if (refreshToken) storage?.setItem(REFRESH_TOKEN_KEY, refreshToken);
  } catch {
    // ignore
  }
  notify();
}

export function clearSession(): void {
  memoryAccessToken = null;
  memoryRefreshToken = null;
  memoryUser = null;

  try {
    const storage = safeStorage();
    storage?.removeItem(ACCESS_TOKEN_KEY);
    storage?.removeItem(REFRESH_TOKEN_KEY);
    storage?.removeItem(USER_KEY);
  } catch {
    // ignore
  }
  notify();
}

export function subscribeSession(listener: SessionListener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function notify(): void {
  for (const listener of listeners) listener();
}

export function hasRole(user: AuthUser | null, roles: UserRole[]): boolean {
  return Boolean(user && roles.includes(user.role));
}

export interface StoredSession {
  accessToken: string;
  refreshToken?: string;
  user: AuthUser;
}

export function getStoredSession(): StoredSession | null {
  const token = getAccessToken();
  const user = getStoredUser();
  if (!token || !user) return null;
  return {
    accessToken: token,
    refreshToken: getRefreshToken() || undefined,
    user,
  };
}

export function setStoredSession(session: { accessToken: string; refreshToken?: string; user: AuthUser }): void {
  setSession({
    tokens: {
      accessToken: session.accessToken,
      refreshToken: session.refreshToken || '',
      tokenType: 'Bearer',
      expiresIn: 3600,
    },
    user: session.user,
  });
}

export const clearStoredSession = clearSession;

