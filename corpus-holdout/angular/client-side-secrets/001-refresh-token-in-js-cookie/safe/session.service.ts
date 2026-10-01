import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { tap } from 'rxjs/operators';

interface Tokens {
  accessToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionService {
  private accessToken: string | null = null;

  constructor(private http: HttpClient) {}

  login(email: string, password: string) {
    return this.http.post<Tokens>('/api/login', { email, password }, { withCredentials: true }).pipe(
      tap((tokens) => {
        this.accessToken = tokens.accessToken;
      }),
    );
  }
}
