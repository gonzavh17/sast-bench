import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { redact } from './redact';

export interface SignupForm {
  email: string;
  credentials: {
    password: string;
    recoveryCode: string;
  };
}

@Injectable({ providedIn: 'root' })
export class SignupService {
  constructor(private http: HttpClient) {}

  register(form: SignupForm) {
    console.info('signup attempt', redact({ ...form }));
    return this.http.post('/api/signup', form);
  }
}
