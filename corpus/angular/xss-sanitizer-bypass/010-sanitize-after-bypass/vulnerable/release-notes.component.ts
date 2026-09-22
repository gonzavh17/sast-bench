import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

import { toSafeHtml } from './trusted-html';

@Component({
  selector: 'app-release-notes',
  templateUrl: './release-notes.component.html',
})
export class ReleaseNotesComponent implements OnInit {
  notes: SafeHtml | null = null;

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    const raw = this.route.snapshot.queryParamMap.get('notes') ?? '';
    this.notes = toSafeHtml(this.sanitizer, raw);
  }
}
