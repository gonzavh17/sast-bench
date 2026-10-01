import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeUrl } from '@angular/platform-browser';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-link-card',
  template: '<a [href]="website">Visit website</a>',
})
export class LinkCardComponent implements OnInit {
  website: SafeUrl | string = '';

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    const url = this.route.snapshot.queryParamMap.get('website') ?? '';
    this.website = this.sanitizer.bypassSecurityTrustUrl(url);
  }
}
