import { Routes } from '@angular/router';

import { authGuard } from './auth.guard';
import { SettingsComponent } from './settings.component';

export const routes: Routes = [
  { path: 'settings', component: SettingsComponent, canActivate: [authGuard] },
];
