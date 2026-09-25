import { Routes } from '@angular/router';

import { AdminPanelComponent } from './admin-panel.component';
import { adminGuard } from './admin.guard';

export const routes: Routes = [
  { path: 'admin', component: AdminPanelComponent, canActivate: [adminGuard] },
];
