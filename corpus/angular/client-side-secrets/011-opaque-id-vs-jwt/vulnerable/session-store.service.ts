import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class SessionStoreService {
  /** Remembers the session so the UI can resume it. */
  remember(sessionToken: string): void {
    sessionStorage.setItem('session_token', sessionToken);
  }

  recall(): string | null {
    return sessionStorage.getItem('session_token');
  }
}
