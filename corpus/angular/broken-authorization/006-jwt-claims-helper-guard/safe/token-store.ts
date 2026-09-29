import { Injectable } from '@angular/core';

/** Holds the id token in memory for the lifetime of the tab. */
@Injectable({ providedIn: 'root' })
export class TokenStore {
  private token: string | null = null;

  set(token: string): void {
    this.token = token;
  }

  get(): string | null {
    return this.token;
  }
}
