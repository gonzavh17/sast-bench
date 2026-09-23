import { Component, OnInit } from '@angular/core';

import { ProfileService, UserProfile } from './profile.service';

@Component({
  selector: 'app-profile',
  template: '<p>{{ profile?.fullName }}</p>',
})
export class ProfileComponent implements OnInit {
  profile: UserProfile | null = null;

  constructor(private profiles: ProfileService) {}

  ngOnInit(): void {
    this.profiles.current().subscribe((profile) => {
      this.profile = profile;
      console.log('perfil cargado', profile);
    });
  }
}
