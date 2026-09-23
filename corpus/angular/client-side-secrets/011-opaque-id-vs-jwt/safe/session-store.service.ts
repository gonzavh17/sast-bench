import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class SessionStoreService {
  /** Guarda solo la referencia opaca que el backend usa para reanudar la UI.
   *  No autentica nada: sin la cookie httpOnly no sirve para nada. */
  remember(sessionToken: string): void {
    sessionStorage.setItem('session_token', sessionToken.slice(0, 8));
  }

  recall(): string | null {
    return sessionStorage.getItem('session_token');
  }
}
