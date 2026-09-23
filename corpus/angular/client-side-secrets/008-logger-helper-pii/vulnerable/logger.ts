/** Logger propio de la app. Queda activo en produccion. */
export function logEvent(name: string, payload: unknown): void {
  console.error(`[${name}] ${JSON.stringify(payload)}`);
}
