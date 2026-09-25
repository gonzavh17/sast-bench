import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-admin-panel',
  template: '<li *ngFor="let u of users">{{ u.email }}</li>',
})
export class AdminPanelComponent implements OnInit {
  users: { email: string }[] = [];

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.http.get<{ email: string }[]>('/api/admin/users').subscribe((users) => (this.users = users));
  }
}
