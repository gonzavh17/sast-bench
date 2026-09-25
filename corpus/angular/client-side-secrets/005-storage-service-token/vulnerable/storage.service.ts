import { Injectable } from '@angular/core';

/** Generic wrapper over localStorage, used across the app. */
@Injectable({ providedIn: 'root' })
export class StorageService {
  save(key: string, value: string): void {
    localStorage.setItem(key, value);
  }

  read(key: string): string | null {
    return localStorage.getItem(key);
  }
}
