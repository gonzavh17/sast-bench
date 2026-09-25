import { Injectable } from '@angular/core';

export interface Session {
  userId: string;
  accessToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionDebugService {
  trace(session: Session): void {
    // console.debug is not stripped from the production build: the level is
    // decided by the browser console, not the compiler.
    console.debug('sesion activa', session);
  }
}
