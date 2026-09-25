import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { Me } from './me';

@Injectable({ providedIn: 'root' })
export class RoleService {
  constructor(private http: HttpClient) {}

  currentRole(): Observable<string> {
    return this.http.get<Me>('/api/me').pipe(map((me) => me.role));
  }
}
