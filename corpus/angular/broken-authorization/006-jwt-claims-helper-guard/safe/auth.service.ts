import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { readClaims } from './jwt';
import { Me } from './me';
import { TokenStore } from './token-store';

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(
    private http: HttpClient,
    private tokens: TokenStore,
  ) {}

  displayName(): string {
    const token = this.tokens.get();
    return token === null ? '' : readClaims(token).sub;
  }

  isAdmin(): Observable<boolean> {
    return this.http.get<Me>('/api/me').pipe(map((me) => me.role === 'admin'));
  }
}
