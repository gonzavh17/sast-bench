import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { tap } from 'rxjs/operators';

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(private http: HttpClient) {}

  login(email: string, password: string) {
    return this.http.post<{ accessToken: string }>('/api/login', { email, password }).pipe(
      tap((response) => {
        localStorage.setItem('access_token', response.accessToken);
      }),
    );
  }
}
