import { HttpClient } from '@angular/common/http';
import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { map } from 'rxjs/operators';

import { Me } from './me';

export const adminGuard: CanActivateFn = () =>
  inject(HttpClient)
    .get<Me>('/api/me')
    .pipe(map((me) => me.role === 'admin'));
