import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from './environment';

@Injectable({ providedIn: 'root' })
export class PaymentService {
  constructor(private http: HttpClient) {}

  charge(amountCents: number) {
    // El backend tiene la clave; el navegador solo pide el cobro y la sesion
    // viaja en una cookie httpOnly que el JS no puede leer.
    return this.http.post(`${environment.apiBaseUrl}/charges`, { amountCents }, {
      withCredentials: true,
    });
  }
}
