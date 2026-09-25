import { HttpClient } from '@angular/common/http';
import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

import { readClaims } from './jwt';

export const adminGuard: CanActivateFn = () => {
  const token = localStorage.getItem('id_token');
  if (token === null) {
    return false;
  }
  const claims = readClaims(token);
  const expired = claims.exp * 1000 < Date.now();
  if (expired) {
    return false;
  }
  return inject(HttpClient)
    .get<{ role: string }>('/api/session', { headers: { Authorization: `Bearer ${token}` } })
    .pipe(
      map((session) => session.role === 'admin'),
      catchError(() => of(false)),
    );
};
