/** Builds the report URL. */
export function buildReportUrl(base: string, reportId: string): string {
  return `${base}/reports/${reportId}`;
}
