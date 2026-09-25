import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class SessionStoreService {
  /** Remembers the session so the UI can resume it.
   *  The backend resumes it from this reference. */
  remember(sessionToken: string): void {
    sessionStorage.setItem('session_token', sessionToken.slice(0, 8));
  }

  recall(): string | null {
    return sessionStorage.getItem('session_token');
  }
}
