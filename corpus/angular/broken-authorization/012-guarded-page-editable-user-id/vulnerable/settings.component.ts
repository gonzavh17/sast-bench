import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-settings',
  template: '<button (click)="deleteAccount()">Borrar mi cuenta</button>',
})
export class SettingsComponent implements OnInit {
  private userId = '';

  constructor(private route: ActivatedRoute, private http: HttpClient) {}

  ngOnInit(): void {
    this.userId = this.route.snapshot.queryParamMap.get('user') ?? '';
  }

  deleteAccount(): void {
    this.http.delete(`/api/users/${this.userId}`).subscribe();
  }
}
