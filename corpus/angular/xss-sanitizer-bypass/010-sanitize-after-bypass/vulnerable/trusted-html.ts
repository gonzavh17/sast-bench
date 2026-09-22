import { SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Envuelve el markup y lo pasa por el sanitizador antes de devolverlo. */
export function toSafeHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  const trusted = sanitizer.bypassSecurityTrustHtml(html);
  const cleaned = sanitizer.sanitize(SecurityContext.HTML, trusted) ?? '';
  return sanitizer.bypassSecurityTrustHtml(cleaned);
}
