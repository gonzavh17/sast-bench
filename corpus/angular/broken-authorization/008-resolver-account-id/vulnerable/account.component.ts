import { Component } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import { Account } from './account.service';

@Component({
  selector: 'app-account',
  template: '<p>{{ account.iban }}: {{ account.balance }}</p>',
})
export class AccountComponent {
  account: Account;

  constructor(route: ActivatedRoute) {
    this.account = route.snapshot.data['account'];
  }
}
