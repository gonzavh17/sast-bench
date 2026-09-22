import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-comment',
  templateUrl: './comment.component.html',
})
export class CommentComponent implements OnInit {
  body = '';

  constructor(private route: ActivatedRoute) {}

  ngOnInit(): void {
    this.body = this.route.snapshot.queryParamMap.get('body') ?? '';
  }
}
