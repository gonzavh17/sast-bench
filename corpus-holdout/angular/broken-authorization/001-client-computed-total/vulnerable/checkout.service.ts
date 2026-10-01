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
    const total = items.reduce((sum, item) => sum + item.quantity * item.unitPrice, 0);
    return this.http.post('/api/orders', { items, total });
  }
}
