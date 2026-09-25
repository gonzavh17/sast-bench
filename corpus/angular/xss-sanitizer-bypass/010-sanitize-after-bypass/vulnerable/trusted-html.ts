import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Wraps the markup and runs it through the sanitizer before returning it. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const trusted = sanitizer.bypassSecurityTrustHtml(html);
  const cleaned = sanitizer.sanitize(SecurityContext.HTML, trusted) ?? '';
  return sanitizer.bypassSecurityTrustHtml(cleaned);
}
