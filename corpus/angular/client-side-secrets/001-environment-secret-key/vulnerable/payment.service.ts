import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from './environment';

@Injectable({ providedIn: 'root' })
export class PaymentService {
  constructor(private http: HttpClient) {}

  charge(amountCents: number) {
    const headers = new HttpHeaders({
      Authorization: `Bearer ${environment.stripeSecretKey}`,
    });
    return this.http.post(`${environment.apiBaseUrl}/charges`, { amountCents }, { headers });
  }
}
