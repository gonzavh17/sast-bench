import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from './environment';

@Injectable({ providedIn: 'root' })
export class PaymentService {
  constructor(private http: HttpClient) {}

  charge(amountCents: number) {
    // Ask the backend for the charge,
    // sending the session cookie along.
    return this.http.post(`${environment.apiBaseUrl}/charges`, { amountCents }, {
      withCredentials: true,
    });
  }
}
