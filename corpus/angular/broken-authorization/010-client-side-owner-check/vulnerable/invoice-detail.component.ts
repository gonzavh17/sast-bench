import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { forkJoin } from 'rxjs';

import { Me } from './me';

interface Invoice {
  id: string;
  ownerId: string;
  total: number;
}

@Component({
  selector: 'app-invoice-detail',
  template: '<p *ngIf="invoice">{{ invoice.id }}: {{ invoice.total }}</p>',
})
export class InvoiceDetailComponent implements OnInit {
  invoice: Invoice | null = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private http: HttpClient,
  ) {}

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    forkJoin({
      me: this.http.get<Me>('/api/me'),
      invoice: this.http.get<Invoice>(`/api/invoices/${id}`),
    }).subscribe(({ me, invoice }) => {
      if (invoice.ownerId !== me.id) {
        this.router.navigate(['/forbidden']);
        return;
      }
      this.invoice = invoice;
    });
  }
}
