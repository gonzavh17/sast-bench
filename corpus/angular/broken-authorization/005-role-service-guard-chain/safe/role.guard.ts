import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { map } from 'rxjs/operators';

import { RoleService } from './role.service';

export const roleGuard: CanActivateFn = (route) =>
  inject(RoleService)
    .currentRole()
    .pipe(map((role) => role === route.data['role']));
