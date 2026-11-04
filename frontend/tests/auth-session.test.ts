import { describe, it, expect, beforeEach } from 'vitest';
import {
  getStoredSession,
  setStoredSession,
  clearStoredSession,
  getAccessToken,
  getRefreshToken,
  updateTokens,
} from '../src/lib/auth/session';

describe('Auth Session Store', () => {
  beforeEach(() => {
    clearStoredSession();
  });

  it('stores access token in memory/storage and retrieves sanitized user identity', () => {
    setStoredSession({
      accessToken: 'jwt_mock_token_123',
      refreshToken: 'jwt_refresh_mock_456',
      user: {
        userId: 'usr-1',
        username: 'soc_analyst',
        email: 'analyst@corp.com',
        role: 'SECURITY_ANALYST',
        orgId: 'org-main',
        createdAt: '2026-11-03T00:00:00Z',
      },
    });

    const session = getStoredSession();
    expect(session?.accessToken).toBe('jwt_mock_token_123');
    expect(session?.refreshToken).toBe('jwt_refresh_mock_456');
    expect(session?.user.role).toBe('SECURITY_ANALYST');
    expect(getAccessToken()).toBe('jwt_mock_token_123');
    expect(getRefreshToken()).toBe('jwt_refresh_mock_456');
  });

  it('updates rotated access and refresh tokens without clobbering user object', () => {
    setStoredSession({
      accessToken: 'jwt_old_token',
      refreshToken: 'jwt_old_refresh',
      user: {
        userId: 'usr-2',
        username: 'sec_admin',
        email: 'admin@corp.com',
        role: 'ORG_ADMIN',
        orgId: 'org-main',
        createdAt: '2026-11-03T00:00:00Z',
      },
    });

    updateTokens('jwt_new_token', 'jwt_new_refresh');
    const session = getStoredSession();
    expect(session?.accessToken).toBe('jwt_new_token');
    expect(session?.refreshToken).toBe('jwt_new_refresh');
    expect(session?.user.username).toBe('sec_admin');
    expect(getAccessToken()).toBe('jwt_new_token');
  });

  it('clears stored session and purges tokens upon logout', () => {
    setStoredSession({
      accessToken: 'temp_token',
      user: {
        userId: 'usr-3',
        username: 'temp',
        email: 'temp@corp.com',
        role: 'READ_ONLY_VIEWER',
        orgId: 'org-main',
        createdAt: '2026-11-03T00:00:00Z',
      },
    });

    clearStoredSession();
    expect(getStoredSession()).toBeNull();
    expect(getAccessToken()).toBeNull();
  });
});
