import { Routes } from '@angular/router';

import { AccountComponent } from './account.component';
import { accountResolver } from './account.resolver';

export const routes: Routes = [
  { path: 'account', component: AccountComponent, resolve: { account: accountResolver } },
];
