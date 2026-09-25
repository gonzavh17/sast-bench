import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

interface Invoice {
  number: string;
  total: number;
}

@Component({
  selector: 'app-invoices',
  template: '<li *ngFor="let i of invoices">{{ i.number }} - {{ i.total }}</li>',
})
export class InvoicesComponent implements OnInit {
  invoices: Invoice[] = [];

  constructor(private route: ActivatedRoute, private http: HttpClient) {}

  ngOnInit(): void {
    const userId = this.route.snapshot.paramMap.get('userId');
    this.http.get<Invoice[]>(`/api/users/${userId}/invoices`).subscribe((list) => (this.invoices = list));
  }
}
