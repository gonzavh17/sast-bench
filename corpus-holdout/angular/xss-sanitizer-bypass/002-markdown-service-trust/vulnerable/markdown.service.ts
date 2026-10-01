import { Injectable } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { marked } from 'marked';

@Injectable({ providedIn: 'root' })
export class MarkdownService {
  constructor(private sanitizer: DomSanitizer) {}

  render(source: string): SafeHtml {
    const html = marked.parse(source, { async: false }) as string;
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }
}
