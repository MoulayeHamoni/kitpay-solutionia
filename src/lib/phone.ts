/**
 * Canonicalize a Mauritanian phone number to bare 8 digits.
 *
 * Examples:
 *   canonicalMauritanianPhone('+222 46 11 22 33') => '46112233'
 *   canonicalMauritanianPhone('46112233')          => '46112233'
 *   canonicalMauritanianPhone('22246112233')        => '46112233'
 */
export function canonicalMauritanianPhone(raw: string): string {
  // Keep only digits. Strip leading country code (222) if the result is longer than 8 digits.
  const digits = (raw ?? '').replace(/\D/g, '');
  if (digits.length === 8) return digits;
  if (digits.length === 11 && digits.startsWith('222')) return digits.slice(3);
  if (digits.length > 8) return digits.slice(-8);  // best-effort last 8
  return digits;  // too short — let downstream validate
}
