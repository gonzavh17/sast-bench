import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

/** Envuelve el markup para poder bindearlo con [innerHTML]. */
export function toTrustedHtml(sanitizer: DomSanitizer, html: string): SafeHtml {
  return sanitizer.bypassSecurityTrustHtml(html);
}
