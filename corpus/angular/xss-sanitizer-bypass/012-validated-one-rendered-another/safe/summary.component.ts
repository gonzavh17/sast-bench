import { Component, OnInit, SecurityContext } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-summary',
  templateUrl: './summary.component.html',
})
export class SummaryComponent implements OnInit {
  summary: SafeHtml | null = null;

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    const raw = this.route.snapshot.queryParamMap.get('summary') ?? '';
    const clean = this.sanitizer.sanitize(SecurityContext.HTML, raw) ?? '';
    if (clean.length === 0) {
      return;
    }
    this.summary = this.sanitizer.bypassSecurityTrustHtml(clean);
  }
}
