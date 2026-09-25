import { CanActivateFn } from '@angular/router';

export const adminGuard: CanActivateFn = () => {
  const role = localStorage.getItem('role');
  return role === 'admin';
};
