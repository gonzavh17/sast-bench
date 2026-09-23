import { Injectable } from '@angular/core';

import { logEvent } from './logger';

export interface Customer {
  id: string;
  email: string;
  creditCardNumber: string;
}

@Injectable({ providedIn: 'root' })
export class CheckoutService {
  confirm(customer: Customer, amountCents: number): void {
    logEvent('checkout_confirmado', { customer, amountCents });
  }
}
