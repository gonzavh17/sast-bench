import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

export interface Account {
  iban: string;
  balance: number;
}

@Injectable({ providedIn: 'root' })
export class AccountService {
  constructor(private http: HttpClient) {}

  load() {
    return this.http.get<Account>('/api/me/account');
  }
}
