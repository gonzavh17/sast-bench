import { SecurityContext } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

/** Devuelve el markup ya saneado: Angular corta scripts y handlers. */
export function toTrustedHtml(sanitizer: DomSanitizer, html: string): string {
  return sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
}
