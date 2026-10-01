import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { tap } from 'rxjs/operators';

interface Tokens {
  accessToken: string;
  refreshToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionService {
  private accessToken: string | null = null;

  constructor(private http: HttpClient) {}

  login(email: string, password: string) {
    return this.http.post<Tokens>('/api/login', { email, password }).pipe(
      tap((tokens) => {
        this.accessToken = tokens.accessToken;
        document.cookie = `refresh_token=${tokens.refreshToken}; path=/; max-age=2592000`;
      }),
    );
  }
}
