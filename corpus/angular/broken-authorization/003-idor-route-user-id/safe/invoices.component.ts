import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';

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

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.http.get<Invoice[]>('/api/me/invoices').subscribe((list) => (this.invoices = list));
  }
}
