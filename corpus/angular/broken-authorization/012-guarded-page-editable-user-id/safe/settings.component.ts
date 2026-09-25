import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';

import { Me } from './me';

@Component({
  selector: 'app-settings',
  template: '<button (click)="deleteAccount()">Borrar mi cuenta</button>',
})
export class SettingsComponent implements OnInit {
  private userId = '';

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.http.get<Me>('/api/me').subscribe((me) => (this.userId = me.id));
  }

  deleteAccount(): void {
    this.http.delete(`/api/users/${this.userId}`).subscribe();
  }
}
