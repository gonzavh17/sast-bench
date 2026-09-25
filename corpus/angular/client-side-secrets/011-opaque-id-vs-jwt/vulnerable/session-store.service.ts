import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class SessionStoreService {
  /** Stores the full JWT: whoever reads it can act as the user. */
  remember(sessionToken: string): void {
    sessionStorage.setItem('session_token', sessionToken);
  }

  recall(): string | null {
    return sessionStorage.getItem('session_token');
  }
}
