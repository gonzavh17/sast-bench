/** Builds the report URL. */
export function buildReportUrl(base: string, reportId: string, apiKey: string): string {
  return `${base}/reports/${reportId}?api_key=${encodeURIComponent(apiKey)}`;
}
