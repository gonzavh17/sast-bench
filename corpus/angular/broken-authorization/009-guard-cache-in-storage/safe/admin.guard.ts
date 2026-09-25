import { HttpClient } from '@angular/common/http';
import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { map, tap } from 'rxjs/operators';

import { Me } from './me';

let cachedRole: string | null = null;

export const adminGuard: CanActivateFn = () => {
  if (cachedRole !== null) {
    return cachedRole === 'admin';
  }
  return inject(HttpClient)
    .get<Me>('/api/me')
    .pipe(
      tap((me) => (cachedRole = me.role)),
      map((me) => me.role === 'admin'),
    );
};
