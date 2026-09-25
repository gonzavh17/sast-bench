/** Builds the report URL. It does not know `apiKey` is a secret. */
export function buildReportUrl(base: string, reportId: string, apiKey: string): string {
  return `${base}/reports/${reportId}?api_key=${encodeURIComponent(apiKey)}`;
}
