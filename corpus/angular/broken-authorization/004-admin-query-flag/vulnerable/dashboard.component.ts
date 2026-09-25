import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

interface User {
  id: string;
  email: string;
}

@Component({
  selector: 'app-dashboard',
  template: `
    <section *ngIf="adminMode">
      <li *ngFor="let u of users">{{ u.email }} <button (click)="ban(u.id)">Bloquear</button></li>
    </section>
  `,
})
export class DashboardComponent implements OnInit {
  adminMode = false;
  users: User[] = [];

  constructor(private route: ActivatedRoute, private http: HttpClient) {}

  ngOnInit(): void {
    this.adminMode = this.route.snapshot.queryParamMap.get('admin') === '1';
    if (this.adminMode) {
      this.http.get<User[]>('/api/admin/users').subscribe((users) => (this.users = users));
    }
  }

  ban(id: string): void {
    this.http.post(`/api/admin/users/${id}/ban`, {}).subscribe();
  }
}
