import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Wraps the markup so it can be bound with [innerHTML]. */
export function toTrustedHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  return sanitizer.bypassSecurityTrustHtml(html);
}
