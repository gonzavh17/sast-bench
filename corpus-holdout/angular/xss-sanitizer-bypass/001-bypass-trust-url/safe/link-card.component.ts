import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-link-card',
  template: '<a [href]="website">Visit website</a>',
})
export class LinkCardComponent implements OnInit {
  website = '';

  constructor(private route: ActivatedRoute) {}

  ngOnInit(): void {
    this.website = this.route.snapshot.queryParamMap.get('website') ?? '';
  }
}
