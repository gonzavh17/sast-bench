import { Component, OnInit } from '@angular/core';

import { ProfileBioService } from './profile-bio.service';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
})
export class ProfileComponent implements OnInit {
  bio = '';

  constructor(private bios: ProfileBioService) {}

  ngOnInit(): void {
    this.bio = this.bios.currentBio();
  }
}
