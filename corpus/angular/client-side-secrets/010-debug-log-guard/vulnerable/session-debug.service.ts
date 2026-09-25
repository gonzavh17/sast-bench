import { Injectable } from '@angular/core';

export interface Session {
  userId: string;
  accessToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionDebugService {
  trace(session: Session): void {
    // Trace the active session
    // while debugging.
    console.debug('sesion activa', session);
  }
}
