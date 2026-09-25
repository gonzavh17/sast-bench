import { CanActivateFn } from '@angular/router';

import { readClaims } from './jwt';

export const adminGuard: CanActivateFn = () => {
  const token = localStorage.getItem('id_token');
  if (token === null) {
    return false;
  }
  const claims = readClaims(token);
  const expired = claims.exp * 1000 < Date.now();
  return !expired && claims.role === 'admin';
};
