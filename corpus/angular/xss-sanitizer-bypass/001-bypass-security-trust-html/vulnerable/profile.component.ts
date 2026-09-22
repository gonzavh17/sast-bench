import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
})
export class ProfileComponent implements OnInit {
  safeBio: SafeHtml | null = null;

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    const bio = this.route.snapshot.queryParamMap.get('bio') ?? '';
    this.safeBio = this.sanitizer.bypassSecurityTrustHtml(bio);
  }
}
