import { Component, OnInit } from '@angular/core';

import { environment } from './environment';

declare const Stripe: (key: string) => unknown;

@Component({
  selector: 'app-checkout',
  template: '<div id="card-element"></div>',
})
export class CheckoutComponent implements OnInit {
  ngOnInit(): void {
    Stripe(environment.stripeKey);
  }
}
