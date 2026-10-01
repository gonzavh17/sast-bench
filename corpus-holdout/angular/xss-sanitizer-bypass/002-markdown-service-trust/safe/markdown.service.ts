import { Injectable, SecurityContext } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import { marked } from 'marked';

@Injectable({ providedIn: 'root' })
export class MarkdownService {
  constructor(private sanitizer: DomSanitizer) {}

  render(source: string): string {
    const html = marked.parse(source, { async: false }) as string;
    return this.sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
  }
}
