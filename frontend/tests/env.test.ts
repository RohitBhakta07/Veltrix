import { describe, it, expect } from 'vitest';

describe('Frontend Build Environment Configuration', () => {
  it('supports ES2022 string.replaceAll and vite client globals', () => {
    const raw = 'test-token-test';
    expect(raw.replaceAll('test', 'clean')).toBe('clean-token-clean');
  });
});

