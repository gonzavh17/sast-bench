/** The app's own event logger. */
export function logEvent(name: string, payload: unknown): void {
  console.error(`[${name}] ${JSON.stringify(payload)}`);
}
