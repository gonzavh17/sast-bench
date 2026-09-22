import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

import { toSafeHtml } from './trusted-html';

@Component({
  selector: 'app-digest',
  templateUrl: './digest.component.html',
})
export class DigestComponent implements OnInit {
  digest: SafeHtml | null = null;

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    const raw = this.route.snapshot.queryParamMap.get('digest') ?? '';
    this.digest = toSafeHtml(this.sanitizer, raw);
  }
}
