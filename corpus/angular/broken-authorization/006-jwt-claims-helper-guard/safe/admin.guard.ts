import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';

import { AuthService } from './auth.service';

export const adminGuard: CanActivateFn = () => inject(AuthService).isAdmin();
