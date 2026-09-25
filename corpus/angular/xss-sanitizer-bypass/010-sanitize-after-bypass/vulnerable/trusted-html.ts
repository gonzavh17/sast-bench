import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Sanitizes the markup and prepares it for [innerHTML]. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const trusted = sanitizer.bypassSecurityTrustHtml(html);
  const cleaned = sanitizer.sanitize(SecurityContext.HTML, trusted) ?? '';
  return sanitizer.bypassSecurityTrustHtml(cleaned);
}
