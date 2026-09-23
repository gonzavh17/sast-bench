import { Injectable, isDevMode } from '@angular/core';

export interface Session {
  userId: string;
  accessToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionDebugService {
  trace(session: Session): void {
    if (!isDevMode()) {
      return;
    }
    console.debug('sesion activa', session.userId);
  }
}
