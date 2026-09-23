import { Injectable } from '@angular/core';

/** Envoltorio generico sobre localStorage, usado por toda la app. */
@Injectable({ providedIn: 'root' })
export class StorageService {
  save(key: string, value: string): void {
    localStorage.setItem(key, value);
  }

  read(key: string): string | null {
    return localStorage.getItem(key);
  }
}
