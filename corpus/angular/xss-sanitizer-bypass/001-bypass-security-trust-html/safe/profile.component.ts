import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
})
export class ProfileComponent implements OnInit {
  bio = '';

  constructor(private route: ActivatedRoute) {}

  ngOnInit(): void {
    this.bio = this.route.snapshot.queryParamMap.get('bio') ?? '';
  }
}
