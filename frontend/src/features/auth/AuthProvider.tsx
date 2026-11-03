import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import type { AuthUser, UserRole } from '@veltrix/shared';
import {
  clearSession,
  getRefreshToken,
  getStoredUser,
  hasRole,
  setSession,
  subscribeSession,
} from '../../lib/auth/session';
import { demoLogin as demoLoginRequest, login as loginRequest, logout as logoutRequest } from '../../lib/api/endpoints';

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoggingIn: boolean;
  error: string | null;
  login: (email: string, password: string, orgId?: string) => Promise<void>;
  demoLogin: (role: UserRole) => Promise<void>;
  logout: () => Promise<void>;
  can: (roles: UserRole[]) => boolean;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(() => getStoredUser());
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => subscribeSession(() => setUser(getStoredUser())), []);

  const login = useCallback(async (email: string, password: string, orgId?: string) => {
    setIsLoggingIn(true);
    setError(null);
    try {
      const response = await loginRequest(email, password, orgId);
      setSession(response.data);
      setUser(response.data.user);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to sign in';
      setError(message);
      throw err;
    } finally {
      setIsLoggingIn(false);
    }
  }, []);

  const demoLogin = useCallback(async (role: UserRole) => {
    setIsLoggingIn(true);
    setError(null);
    try {
      const response = await demoLoginRequest(role);
      setSession(response.data);
      setUser(response.data.user);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Demo access is unavailable on this backend';
      setError(message);
      throw err;
    } finally {
      setIsLoggingIn(false);
    }
  }, []);

  const logout = useCallback(async () => {
    const refreshToken = getRefreshToken() || undefined;
    try {
      await logoutRequest(refreshToken);
    } catch {
      // Local sign-out must succeed even if the API is unreachable.
    } finally {
      clearSession();
      setUser(null);
    }
  }, []);

  const can = useCallback((roles: UserRole[]) => hasRole(user, roles), [user]);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated: Boolean(user),
      isLoggingIn,
      error,
      login,
      demoLogin,
      logout,
      can,
      clearError: () => setError(null),
    }),
    [user, isLoggingIn, error, login, demoLogin, logout, can]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside AuthProvider');
  return context;
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}

export function PermissionGate({
  roles,
  children,
  fallback = null,
}: {
  roles: UserRole[];
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const { can } = useAuth();
  return <>{can(roles) ? children : fallback}</>;
}
