import { Injectable } from '@angular/core';

import { persist } from './persist';

export interface AuthState {
  userId: string;
  displayName: string;
  accessToken: string;
  theme: 'light' | 'dark';
}

@Injectable({ providedIn: 'root' })
export class AuthStore {
  private state: AuthState = { userId: '', displayName: '', accessToken: '', theme: 'light' };

  update(patch: Partial<AuthState>): void {
    this.state = { ...this.state, ...patch };
    persist('ui', { theme: this.state.theme });
  }

  snapshot(): AuthState {
    return this.state;
  }
}
