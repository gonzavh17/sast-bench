export interface TokenClaims {
  sub: string;
  role: string;
  exp: number;
}

export function readClaims(token: string): TokenClaims {
  const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(atob(payload));
}
