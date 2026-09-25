import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-login',
  template: '<button (click)="submit()">Entrar</button>',
})
export class LoginComponent {
  email = '';
  password = '';

  constructor(private http: HttpClient) {}

  submit(): void {
    // The body goes through the error interceptor before reaching anything else.
    this.http.post('/api/login', { email: this.email, password: this.password }).subscribe();
  }
}
