import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';

import { readClaims } from './jwt';
import { TokenStore } from './token-store';

export const adminGuard: CanActivateFn = () => {
  const token = inject(TokenStore).get();
  if (token === null) {
    return false;
  }
  const claims = readClaims(token);
  const expired = claims.exp * 1000 < Date.now();
  return !expired && claims.role === 'admin';
};
