/** Arma la URL del reporte. No sabe que `apiKey` es un secreto. */
export function buildReportUrl(base: string, reportId: string, apiKey: string): string {
  return `${base}/reports/${reportId}?api_key=${encodeURIComponent(apiKey)}`;
}
