import { describe, it, expect } from 'vitest';
import { redactSecrets, sanitizeObject } from '../src/security/secret-redactor.js';

describe('SecretRedactor - Credential Sanitization & Terminal Protection', () => {
  describe('redactSecrets text string redaction', () => {
    it('redacts Authorization Bearer tokens in headers and logs', () => {
      const input = 'Request headers: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-z8';
      const redacted = redactSecrets(input);
      expect(redacted).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(redacted).toContain('Bearer [REDACTED]');
    });

    it('redacts standalone JWT tokens', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature_goes_here';
      const input = `Session token is: ${jwt}`;
      const redacted = redactSecrets(input);
      expect(redacted).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(redacted).toContain('[REDACTED_JWT]');
    });

    it('redacts veltrix platform tokens (vltx_tok_* and vltx_key_*)', () => {
      const input = 'Using token vltx_tok_9f8a7b6c5d4e3f2a1b0c and key vltx_key_11223344556677889900';
      const redacted = redactSecrets(input);
      expect(redacted).not.toContain('vltx_tok_9f8a7b6c5d4e3f2a1b0c');
      expect(redacted).not.toContain('vltx_key_11223344556677889900');
      expect(redacted).toContain('vltx_tok_[REDACTED]');
      expect(redacted).toContain('vltx_key_[REDACTED]');
    });

    it('redacts vltx_tok_* containing alphanumeric characters, hyphens, and mixed case', () => {
      const input = 'Token: vltx_tok_SecureJWTToken-XYZ_9999';
      const redacted = redactSecrets(input);
      expect(redacted).not.toContain('vltx_tok_SecureJWTToken-XYZ_9999');
      expect(redacted).toBe('Token: vltx_tok_[REDACTED]');
    });

    it('redacts URL basic authentication credentials', () => {
      const input = 'Connecting to https://soc_admin:superSecretP@ss!@internal.domain/api';
      const redacted = redactSecrets(input);
      expect(redacted).not.toContain('superSecretP@ss!');
      expect(redacted).toContain('soc_admin:[REDACTED]@internal.domain');
    });

    it('redacts password key-value assignments', () => {
      const input = 'config: password="mySecretPassword123" client_secret=\'xyz987\'';
      const redacted = redactSecrets(input);
      expect(redacted).not.toContain('mySecretPassword123');
      expect(redacted).not.toContain('xyz987');
      expect(redacted).toContain('password="[REDACTED]"');
    });
  });

  describe('sanitizeObject deep object sanitization', () => {
    it('redacts sensitive keys in nested object structures', () => {
      const sensitiveData = {
        user: {
          id: 'usr_123',
          email: 'analyst@veltrix.internal',
          password: 'plainTextPassword!',
          tokens: {
            accessToken: 'vltx_tok_abc1234567890def',
            refreshToken: 'vltx_tok_refreshSecret123',
          },
        },
        settings: {
          apiKey: 'secret_key_value',
          publicSetting: 'allowed_value',
          secretKey: 'integration_secret_live',
          signingKey: 'kms_signing_key_hex',
          signingSecret: 'hmac_signing_secret',
          sessionToken: 'temporary_session_token',
        },
      };

      const sanitized = sanitizeObject(sensitiveData);

      expect(sanitized.user.id).toBe('usr_123');
      expect(sanitized.user.email).toBe('analyst@veltrix.internal');
      expect(sanitized.user.password).toBe('[REDACTED]');
      expect(sanitized.user.tokens.accessToken).toBe('[REDACTED]');
      expect(sanitized.user.tokens.refreshToken).toBe('[REDACTED]');
      expect(sanitized.settings.apiKey).toBe('[REDACTED]');
      expect(sanitized.settings.secretKey).toBe('[REDACTED]');
      expect(sanitized.settings.signingKey).toBe('[REDACTED]');
      expect(sanitized.settings.signingSecret).toBe('[REDACTED]');
      expect(sanitized.settings.sessionToken).toBe('[REDACTED]');
      expect(sanitized.settings.publicSetting).toBe('allowed_value');
    });

    it('handles arrays, null, undefined, and non-object primitives safely', () => {
      expect(sanitizeObject(null)).toBe(null);
      expect(sanitizeObject(undefined)).toBe(undefined);
      expect(sanitizeObject(12345)).toBe(12345);
      expect(sanitizeObject('normal string')).toBe('normal string');

      const arr = [{ password: 'secret1' }, { token: 'secret2' }, { name: 'safe' }];
      const sanitizedArr = sanitizeObject(arr);
      expect(sanitizedArr[0].password).toBe('[REDACTED]');
      expect(sanitizedArr[1].token).toBe('[REDACTED]');
      expect(sanitizedArr[2].name).toBe('safe');
    });
  });
});

