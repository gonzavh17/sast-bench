import { inject } from '@angular/core';
import { ResolveFn } from '@angular/router';

import { Account, AccountService } from './account.service';

export const accountResolver: ResolveFn<Account> = (route) =>
  inject(AccountService).load(route.paramMap.get('accountId') ?? '');
