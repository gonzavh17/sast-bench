import { Routes } from '@angular/router';

import { ReportsComponent } from './reports.component';
import { roleGuard } from './role.guard';

export const routes: Routes = [
  {
    path: 'reports',
    component: ReportsComponent,
    canActivate: [roleGuard],
    data: { role: 'finance' },
  },
];
