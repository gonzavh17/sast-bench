import { HttpClient } from '@angular/common/http';
import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

import { Me } from './me';

export const authGuard: CanActivateFn = () =>
  inject(HttpClient)
    .get<Me>('/api/me')
    .pipe(
      map(() => true),
      catchError(() => of(false)),
    );
