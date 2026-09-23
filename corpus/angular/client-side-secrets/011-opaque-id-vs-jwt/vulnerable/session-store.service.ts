import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class SessionStoreService {
  /** Guarda el JWT completo: quien lo lea puede actuar como el usuario. */
  remember(sessionToken: string): void {
    sessionStorage.setItem('session_token', sessionToken);
  }

  recall(): string | null {
    return sessionStorage.getItem('session_token');
  }
}
