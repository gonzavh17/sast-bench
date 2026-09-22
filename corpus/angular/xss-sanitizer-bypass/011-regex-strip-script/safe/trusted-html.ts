import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Saca todo lo ejecutable antes de confiar en el markup. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const stripped = sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
  return sanitizer.bypassSecurityTrustHtml(stripped);
}
