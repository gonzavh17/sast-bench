import { HttpClient } from '@angular/common/http';
import { Component, Input, OnInit } from '@angular/core';

import { MarkdownService } from './markdown.service';

interface Comment {
  author: string;
  body: string;
}

@Component({
  selector: 'app-comment-list',
  templateUrl: './comment-list.component.html',
})
export class CommentListComponent implements OnInit {
  @Input() postId = '';
  comments: Comment[] = [];

  constructor(
    private http: HttpClient,
    public markdown: MarkdownService,
  ) {}

  ngOnInit(): void {
    this.http.get<Comment[]>(`/api/posts/${this.postId}/comments`).subscribe((list) => (this.comments = list));
  }
}
