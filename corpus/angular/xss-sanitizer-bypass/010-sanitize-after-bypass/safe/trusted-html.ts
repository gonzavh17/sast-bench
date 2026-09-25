import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Runs the markup through the sanitizer and only then wraps it. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const cleaned = sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
  return sanitizer.bypassSecurityTrustHtml(cleaned);
}
