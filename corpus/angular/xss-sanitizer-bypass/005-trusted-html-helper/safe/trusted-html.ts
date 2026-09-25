import { SecurityContext } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

/** Prepares the markup for an [innerHTML] binding. */
export function toTrustedHtml(sanitizer: DomSanitizer, html: string): string {
  return sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
}
