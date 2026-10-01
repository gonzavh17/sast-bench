import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

export interface CartItem {
  sku: string;
  quantity: number;
  unitPrice: number;
}

@Injectable({ providedIn: 'root' })
export class CheckoutService {
  constructor(private http: HttpClient) {}

  placeOrder(items: CartItem[]) {
    const lines = items.map(({ sku, quantity }) => ({ sku, quantity }));
    return this.http.post('/api/orders', { items: lines });
  }
}
