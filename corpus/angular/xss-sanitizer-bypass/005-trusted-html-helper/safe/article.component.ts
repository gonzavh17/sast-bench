import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

import { toTrustedHtml } from './trusted-html';

@Component({
  selector: 'app-article',
  templateUrl: './article.component.html',
})
export class ArticleComponent implements OnInit {
  safeBody: SafeHtml | string = '';

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    const body = this.route.snapshot.queryParamMap.get('body') ?? '';
    this.safeBody = toTrustedHtml(this.sanitizer, body);
  }
}
