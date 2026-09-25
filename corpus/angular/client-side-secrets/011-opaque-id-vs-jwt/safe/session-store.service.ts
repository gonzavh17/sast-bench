import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class SessionStoreService {
  /** Stores only the opaque reference the backend uses to resume the UI.
   *  It authenticates nothing: without the httpOnly cookie it is useless. */
  remember(sessionToken: string): void {
    sessionStorage.setItem('session_token', sessionToken.slice(0, 8));
  }

  recall(): string | null {
    return sessionStorage.getItem('session_token');
  }
}
