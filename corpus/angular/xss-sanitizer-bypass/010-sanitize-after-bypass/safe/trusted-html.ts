import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Sanitizes the markup and prepares it for [innerHTML]. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const cleaned = sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
  return sanitizer.bypassSecurityTrustHtml(cleaned);
}
