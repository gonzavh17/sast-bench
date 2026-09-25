import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

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
    this.http.get<Invoice>(`/api/me/invoices/${id}`).subscribe({
      next: (invoice) => (this.invoice = invoice),
      error: (err: HttpErrorResponse) => {
        if (err.status === 404) {
          this.router.navigate(['/forbidden']);
        }
      },
    });
  }
}
