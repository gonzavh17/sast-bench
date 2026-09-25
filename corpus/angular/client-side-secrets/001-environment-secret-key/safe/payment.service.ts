import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from './environment';

@Injectable({ providedIn: 'root' })
export class PaymentService {
  constructor(private http: HttpClient) {}

  charge(amountCents: number) {
    // The backend holds the key; the browser only requests the charge and the session
    // travels in an httpOnly cookie that JS cannot read.
    return this.http.post(`${environment.apiBaseUrl}/charges`, { amountCents }, {
      withCredentials: true,
    });
  }
}
