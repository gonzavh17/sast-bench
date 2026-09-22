import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

import { ProfileBioService } from './profile-bio.service';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
})
export class ProfileComponent implements OnInit {
  safeBio: SafeHtml | null = null;

  constructor(
    private bios: ProfileBioService,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    this.safeBio = this.sanitizer.bypassSecurityTrustHtml(this.bios.currentBio());
  }
}
