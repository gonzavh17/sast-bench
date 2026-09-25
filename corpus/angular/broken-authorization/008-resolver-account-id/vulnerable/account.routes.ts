import { Routes } from '@angular/router';

import { AccountComponent } from './account.component';
import { accountResolver } from './account.resolver';

export const routes: Routes = [
  { path: 'accounts/:accountId', component: AccountComponent, resolve: { account: accountResolver } },
];
