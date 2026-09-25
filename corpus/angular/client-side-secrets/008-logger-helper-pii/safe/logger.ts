/** The app's own logger. It stays active in production. */
export function logEvent(name: string, payload: unknown): void {
  console.error(`[${name}] ${JSON.stringify(payload)}`);
}
