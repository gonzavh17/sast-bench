const SECRET_KEYS = ['email', 'password', 'token', 'recoveryCode'];

export function redact(payload: Record<string, unknown>): Record<string, unknown> {
  const copy: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (SECRET_KEYS.includes(key)) {
      copy[key] = '[redacted]';
    } else if (value !== null && typeof value === 'object') {
      copy[key] = redact(value as Record<string, unknown>);
    } else {
      copy[key] = value;
    }
  }
  return copy;
}
