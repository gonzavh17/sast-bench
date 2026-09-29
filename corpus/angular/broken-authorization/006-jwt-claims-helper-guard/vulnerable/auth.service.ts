import { Injectable } from '@angular/core';

import { readClaims } from './jwt';
import { TokenStore } from './token-store';

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(private tokens: TokenStore) {}

  isAdmin(): boolean {
    const token = this.tokens.get();
    return token !== null && readClaims(token).role === 'admin';
  }
}
