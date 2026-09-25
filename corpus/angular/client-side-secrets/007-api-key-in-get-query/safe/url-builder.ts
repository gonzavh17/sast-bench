/** Builds the report URL. The credential does not travel in the query string. */
export function buildReportUrl(base: string, reportId: string): string {
  return `${base}/reports/${reportId}`;
}
