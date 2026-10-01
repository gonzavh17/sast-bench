const SECRET_KEYS = ['email', 'password', 'token', 'recoveryCode'];

export function redact(payload: Record<string, unknown>): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...payload };
  for (const key of SECRET_KEYS) {
    if (key in copy) {
      copy[key] = '[redacted]';
    }
  }
  return copy;
}
