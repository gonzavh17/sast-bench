import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

const SCRIPT_TAG = /<script[\s\S]*?<\/script>/gi;

/** Strips <script> tags before trusting the markup. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const stripped = html.replace(SCRIPT_TAG, '');
  return sanitizer.bypassSecurityTrustHtml(stripped);
}
