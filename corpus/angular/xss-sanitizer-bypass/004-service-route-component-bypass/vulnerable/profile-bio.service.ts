import { Injectable } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class ProfileBioService {
  constructor(private route: ActivatedRoute) {}

  currentBio(): string {
    return this.route.snapshot.queryParamMap.get('bio') ?? '';
  }
}
