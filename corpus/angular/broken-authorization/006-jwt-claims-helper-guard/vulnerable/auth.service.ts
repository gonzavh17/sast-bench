import { Injectable } from '@angular/core';

import { readClaims } from './jwt';

@Injectable({ providedIn: 'root' })
export class AuthService {
  isAdmin(): boolean {
    const token = localStorage.getItem('id_token');
    return token !== null && readClaims(token).role === 'admin';
  }
}
