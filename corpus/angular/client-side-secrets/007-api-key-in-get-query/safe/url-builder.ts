/** Arma la URL del reporte. La credencial no viaja en la query string. */
export function buildReportUrl(base: string, reportId: string): string {
  return `${base}/reports/${reportId}`;
}
