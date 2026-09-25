import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { tap } from 'rxjs/operators';

import { StorageService } from './storage.service';

@Injectable({ providedIn: 'root' })
export class SessionService {
  private accessToken: string | null = null;

  constructor(private http: HttpClient, private storage: StorageService) {}

  start(email: string, password: string) {
    return this.http.post<{ accessToken: string }>('/api/login', { email, password }).pipe(
      tap((response) => {
        this.accessToken = response.accessToken;
        // Only the language preference goes to disk, not the credential.
        this.storage.save('locale', 'es-AR');
      }),
    );
  }
}
