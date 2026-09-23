import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';

const ALLOWED_ORIGIN = 'https://cdn.example.com';

@Component({
  selector: 'app-preview',
  templateUrl: './preview.component.html',
})
export class PreviewComponent implements OnInit {
  safeSrc: SafeResourceUrl | null = null;

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    const src = this.route.snapshot.queryParamMap.get('src') ?? '';
    if (!src.startsWith(ALLOWED_ORIGIN)) {
      return;
    }
    this.safeSrc = this.sanitizer.bypassSecurityTrustResourceUrl(src);
  }
}
