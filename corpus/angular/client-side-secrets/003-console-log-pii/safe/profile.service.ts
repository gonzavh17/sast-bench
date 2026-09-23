import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

export interface UserProfile {
  id: string;
  fullName: string;
  email: string;
  nationalId: string;
  password: string;
}

@Injectable({ providedIn: 'root' })
export class ProfileService {
  constructor(private http: HttpClient) {}

  current() {
    return this.http.get<UserProfile>('/api/me');
  }
}
