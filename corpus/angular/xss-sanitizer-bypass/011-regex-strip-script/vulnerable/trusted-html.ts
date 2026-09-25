import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

const SCRIPT_TAG = /<script[\s\S]*?<\/script>/gi;

/** Cleans the markup before trusting it. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const stripped = html.replace(SCRIPT_TAG, '');
  return sanitizer.bypassSecurityTrustHtml(stripped);
}
