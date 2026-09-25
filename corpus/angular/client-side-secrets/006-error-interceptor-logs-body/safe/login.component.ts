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
    // Submit the login form.
    this.http.post('/api/login', { email: this.email, password: this.password }).subscribe();
  }
}
