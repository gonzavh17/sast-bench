import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-reports',
  template: '<pre>{{ report | json }}</pre>',
})
export class ReportsComponent implements OnInit {
  report: unknown = null;

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.http.get('/api/reports/payroll').subscribe((report) => (this.report = report));
  }
}
