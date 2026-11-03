export interface VeltrixProfile {
  apiUrl: string;
  defaultOrgId?: string;
  accessToken?: string;
  token?: string; // alias for accessToken
  refreshToken?: string;
  tokenExpiresAt?: string;
  userEmail?: string;
  orgId?: string;
  user?: {
    userId: string;
    username: string;
    email: string;
    role: string;
    orgId: string;
  };
  outputFormat: 'table' | 'json';
  timeoutMs: number;
}

export interface VeltrixConfigFile {
  version: 1;
  currentProfile: string;
  profiles: Record<string, Partial<VeltrixProfile>>;
}

export interface ResolvedCliConfig {
  apiUrl: string;
  token?: string;
  orgId?: string;
  outputFormat: 'table' | 'json';
  timeoutMs: number;
  profileName: string;
  user?: VeltrixProfile['user'];
  sources: {
    apiUrl: 'cli' | 'env' | 'config' | 'default';
    token: 'cli' | 'env' | 'config' | 'none';
    orgId: 'cli' | 'env' | 'config' | 'none';
    outputFormat: 'cli' | 'env' | 'config' | 'default';
  };
}
