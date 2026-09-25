import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Prepares the markup for an [innerHTML] binding. */
export function toTrustedHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  return sanitizer.bypassSecurityTrustHtml(html);
}
