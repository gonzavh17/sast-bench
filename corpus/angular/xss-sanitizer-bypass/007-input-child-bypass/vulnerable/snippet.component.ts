import { Component, Input, OnChanges } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-snippet',
  templateUrl: './snippet.component.html',
})
export class SnippetComponent implements OnChanges {
  @Input() html = '';

  safeHtml: SafeHtml | string = '';

  constructor(private sanitizer: DomSanitizer) {}

  ngOnChanges(): void {
    this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(this.html);
  }
}
