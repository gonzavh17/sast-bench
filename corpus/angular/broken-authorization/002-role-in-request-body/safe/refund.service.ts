import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class RefundService {
  constructor(private http: HttpClient) {}

  refund(orderId: string) {
    return this.http.post('/api/refunds', { orderId }, { withCredentials: true });
  }
}
