import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Pasa el markup por el sanitizador y recien despues lo envuelve. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const cleaned = sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
  return sanitizer.bypassSecurityTrustHtml(cleaned);
}
