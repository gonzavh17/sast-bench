import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from './environment';
import { buildReportUrl } from './url-builder';

@Injectable({ providedIn: 'root' })
export class ReportsService {
  constructor(private http: HttpClient) {}

  download(reportId: string) {
    const url = buildReportUrl(environment.reportsBaseUrl, reportId);
    // La sesion viaja en una cookie httpOnly: no queda en la URL, ni en el
    // historial del navegador, ni en los logs del proxy.
    return this.http.get(url, { responseType: 'blob', withCredentials: true });
  }
}
