import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-feed',
  templateUrl: './feed.component.html',
})
export class FeedComponent implements OnInit {
  raw = '';

  constructor(private route: ActivatedRoute) {}

  ngOnInit(): void {
    this.raw = this.route.snapshot.queryParamMap.get('snippet') ?? '';
  }
}
