import { HttpClient } from '@angular/common/http';
import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { map, tap } from 'rxjs/operators';

import { Me } from './me';

export const adminGuard: CanActivateFn = () => {
  const cached = localStorage.getItem('me_role');
  if (cached !== null) {
    return cached === 'admin';
  }
  return inject(HttpClient)
    .get<Me>('/api/me')
    .pipe(
      tap((me) => localStorage.setItem('me_role', me.role)),
      map((me) => me.role === 'admin'),
    );
};
