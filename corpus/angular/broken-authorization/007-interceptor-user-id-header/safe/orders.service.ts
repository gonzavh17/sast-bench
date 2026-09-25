import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class OrdersService {
  constructor(private http: HttpClient) {}

  mine() {
    return this.http.get<{ id: string; total: number }[]>('/api/orders');
  }
}
