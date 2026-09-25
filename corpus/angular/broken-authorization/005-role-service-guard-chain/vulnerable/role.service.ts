import { Injectable } from '@angular/core';
import { Observable, of } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class RoleService {
  currentRole(): Observable<string> {
    return of(localStorage.getItem('role') ?? 'guest');
  }
}
