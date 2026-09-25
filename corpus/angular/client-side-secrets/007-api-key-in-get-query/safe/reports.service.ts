import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from './environment';
import { buildReportUrl } from './url-builder';

@Injectable({ providedIn: 'root' })
export class ReportsService {
  constructor(private http: HttpClient) {}

  download(reportId: string) {
    const url = buildReportUrl(environment.reportsBaseUrl, reportId);
    // Download the report,
    // sending the session cookie along.
    return this.http.get(url, { responseType: 'blob', withCredentials: true });
  }
}
