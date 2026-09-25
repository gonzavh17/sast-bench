import { SecurityContext } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

/** Returns the markup already sanitized: Angular strips scripts and handlers. */
export function toTrustedHtml(sanitizer: DomSanitizer, html: string): string {
  return sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
}
