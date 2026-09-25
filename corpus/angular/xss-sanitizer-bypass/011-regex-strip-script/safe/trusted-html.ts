import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Cleans the markup before trusting it. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const stripped = sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
  return sanitizer.bypassSecurityTrustHtml(stripped);
}
