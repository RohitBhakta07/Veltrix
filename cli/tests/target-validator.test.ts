import { describe, it, expect } from 'vitest';
import {
  validateScanTargetClient,
  isPrivateOrReservedIp,
  canonicalizeTarget,
} from '../src/security/target-validator.js';
import { ScopePolicyError, ValidationError } from '../src/client/errors.js';

describe('TargetValidator - Pre-flight Client SSRF and Target Safety', () => {
  describe('Valid Targets', () => {
    it('should accept valid standard HTTPS URL', () => {
      const result = validateScanTargetClient('https://example.com');
      expect(result.isValid).toBe(true);
      expect(result.normalizedUrl).toBe('https://example.com');
      expect(result.hostname).toBe('example.com');
      expect(result.scheme).toBe('https');
      expect(result.port).toBe(443);
    });

    it('should accept valid standard HTTP URL with path', () => {
      const result = validateScanTargetClient('http://sub.domain.example.org/api/v1');
      expect(result.isValid).toBe(true);
      expect(result.normalizedUrl).toBe('http://sub.domain.example.org/api/v1');
      expect(result.hostname).toBe('sub.domain.example.org');
      expect(result.port).toBe(80);
    });

    it('should accept custom permitted web ports (8080, 8443, 3000)', () => {
      const res1 = validateScanTargetClient('https://app.example.com:8443');
      expect(res1.isValid).toBe(true);
      expect(res1.port).toBe(8443);

      const res2 = validateScanTargetClient('http://web.example.com:8080');
      expect(res2.isValid).toBe(true);
      expect(res2.port).toBe(8080);
    });

    it('should canonicalize target without protocol by prepending https://', () => {
      const canonical = canonicalizeTarget('example.com');
      expect(canonical).toBe('https://example.com');
    });
  });

  describe('SSRF Protection - Loopback & Localhost', () => {
    it('should reject localhost hostname', () => {
      expect(() => validateScanTargetClient('http://localhost')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://localhost:8080')).toThrow(ScopePolicyError);
    });

    it('should reject IPv4 loopback 127.0.0.1', () => {
      expect(() => validateScanTargetClient('http://127.0.0.1')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://127.0.0.2:3000')).toThrow(ScopePolicyError);
    });

    it('should reject IPv6 loopback [::1]', () => {
      expect(() => validateScanTargetClient('http://[::1]')).toThrow(ScopePolicyError);
    });
  });

  describe('SSRF Protection - RFC 1918 Private Ranges', () => {
    it('should reject 10.0.0.0/8 addresses', () => {
      expect(() => validateScanTargetClient('http://10.0.0.1')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://10.254.1.5:8080')).toThrow(ScopePolicyError);
    });

    it('should reject 172.16.0.0/12 addresses', () => {
      expect(() => validateScanTargetClient('http://172.16.0.1')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://172.31.255.255')).toThrow(ScopePolicyError);
    });

    it('should reject 192.168.0.0/16 addresses', () => {
      expect(() => validateScanTargetClient('http://192.168.1.1')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://192.168.0.100:8000')).toThrow(ScopePolicyError);
    });

    it('should reject multicast, reserved, and test-net addresses (Finding 6)', () => {
      expect(() => validateScanTargetClient('http://224.0.0.1')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://240.0.0.1')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://198.18.0.1')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://192.0.2.1')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://[ff02::1]')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://[2001:db8::1]')).toThrow(ScopePolicyError);
    });
  });

  describe('SSRF Protection - Cloud Metadata & Link-Local', () => {
    it('should reject AWS/Azure/GCP metadata IP 169.254.169.254', () => {
      expect(() => validateScanTargetClient('http://169.254.169.254/latest/meta-data/')).toThrow(
        ScopePolicyError
      );
    });

    it('should reject IPv6 Link-Local and Unique-Local addresses', () => {
      expect(() => validateScanTargetClient('http://[fe80::1]')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://[fd00::1]')).toThrow(ScopePolicyError);
    });
  });

  describe('SSRF Protection - Port & Protocol Constraints', () => {
    it('should reject prohibited infrastructure and database ports', () => {
      // SSH
      expect(() => validateScanTargetClient('http://example.com:22')).toThrow(ScopePolicyError);
      // SMTP
      expect(() => validateScanTargetClient('http://example.com:25')).toThrow(ScopePolicyError);
      // MySQL
      expect(() => validateScanTargetClient('http://example.com:3306')).toThrow(ScopePolicyError);
      // Postgres
      expect(() => validateScanTargetClient('http://example.com:5432')).toThrow(ScopePolicyError);
      // Redis
      expect(() => validateScanTargetClient('http://example.com:6379')).toThrow(ScopePolicyError);
      // MongoDB
      expect(() => validateScanTargetClient('http://example.com:27017')).toThrow(ScopePolicyError);
    });

    it('should reject non-HTTP schemes', () => {
      expect(() => validateScanTargetClient('file:///etc/passwd')).toThrow(ValidationError);
      expect(() => validateScanTargetClient('ftp://example.com')).toThrow(ValidationError);
      expect(() => validateScanTargetClient('gopher://example.com')).toThrow(ValidationError);
      expect(() => validateScanTargetClient('javascript:alert(1)')).toThrow(ValidationError);
    });

    it('should reject embedded user credentials in URL', () => {
      expect(() => validateScanTargetClient('https://admin:secret@example.com')).toThrow(
        ValidationError
      );
    });

    it('should reject IPv6 Zone IDs', () => {
      expect(() => validateScanTargetClient('http://[fe80::1%eth0]')).toThrow(ScopePolicyError);
    });

    it('should reject internal domain suffixes (.corp, .intranet, .home.arpa, .test)', () => {
      expect(() => validateScanTargetClient('http://internal-vault.corp')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://admin.intranet')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://gateway.home.arpa')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://staging.test')).toThrow(ScopePolicyError);
    });

    it('should reject hex-encoded IPv4-mapped loopback/private IPv6', () => {
      expect(() => validateScanTargetClient('http://[::ffff:7f00:1]')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://[::ffff:a00:1]')).toThrow(ScopePolicyError);
      expect(() => validateScanTargetClient('http://[::ffff:a9fe:a9fe]')).toThrow(ScopePolicyError);
    });
  });

  describe('isPrivateOrReservedIp direct evaluation', () => {
    it('identifies private IPs correctly', () => {
      expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true);
      expect(isPrivateOrReservedIp('10.1.2.3')).toBe(true);
      expect(isPrivateOrReservedIp('172.20.0.1')).toBe(true);
      expect(isPrivateOrReservedIp('192.168.1.1')).toBe(true);
      expect(isPrivateOrReservedIp('169.254.169.254')).toBe(true);
      expect(isPrivateOrReservedIp('8.8.8.8')).toBe(false);
      expect(isPrivateOrReservedIp('93.184.216.34')).toBe(false);
    });
  });
});

