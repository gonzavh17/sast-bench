import { Injectable } from '@angular/core';

export interface Session {
  userId: string;
  accessToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionDebugService {
  trace(session: Session): void {
    // console.debug no se elimina en el build de produccion: el nivel lo
    // decide la consola del navegador, no el compilador.
    console.debug('sesion activa', session);
  }
}
