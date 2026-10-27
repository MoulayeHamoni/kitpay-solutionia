import { describe, it, expect } from 'vitest';
import { generateForwarderToken, hashForwarderToken } from '../../src/lib/forwarders';

describe('generateForwarderToken', () => {
  it('returns a kpf_ prefixed token with base64url alphabet', () => {
    const t = generateForwarderToken();
    expect(t).toMatch(/^kpf_[A-Za-z0-9_-]+$/);
    expect(t.length).toBeGreaterThanOrEqual(24);
  });

  it('generates unique tokens across 500 draws', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 500; i++) seen.add(generateForwarderToken());
    expect(seen.size).toBe(500);
  });
});

describe('hashForwarderToken', () => {
  it('returns a 64-char hex string', () => {
    const h = hashForwarderToken('kpf_abcdefghij1234567890');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic', () => {
    const t = 'kpf_sample_token_value_xyz';
    expect(hashForwarderToken(t)).toBe(hashForwarderToken(t));
  });

  it('distinguishes different inputs', () => {
    expect(hashForwarderToken('a')).not.toBe(hashForwarderToken('b'));
  });
});
