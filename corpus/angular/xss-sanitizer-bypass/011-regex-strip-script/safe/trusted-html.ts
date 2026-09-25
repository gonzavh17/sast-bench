import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Strips everything executable before trusting the markup. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const stripped = sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
  return sanitizer.bypassSecurityTrustHtml(stripped);
}
