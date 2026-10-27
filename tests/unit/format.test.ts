import { describe, it, expect } from 'vitest';
import { generateRef } from '../../src/lib/format';

describe('generateRef', () => {
  it('returns a KP- prefixed ref of 10 alphanumeric uppercase chars', () => {
    const ref = generateRef();
    expect(ref).toMatch(/^KP-[A-Z0-9]{10}$/);
  });

  it('produces 1000 unique refs with no collisions', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(generateRef());
    expect(seen.size).toBe(1000);
  });
});
