export function persist(key: string, state: object): void {
  localStorage.setItem(key, JSON.stringify(state));
}
