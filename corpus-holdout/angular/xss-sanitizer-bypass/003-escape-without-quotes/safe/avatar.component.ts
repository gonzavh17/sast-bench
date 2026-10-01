import { AfterViewInit, Component, ElementRef, ViewChild } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import { escapeHtml } from './escape';

@Component({
  selector: 'app-avatar',
  template: '<span #slot></span>',
})
export class AvatarComponent implements AfterViewInit {
  @ViewChild('slot') slot!: ElementRef<HTMLSpanElement>;

  constructor(private route: ActivatedRoute) {}

  ngAfterViewInit(): void {
    const name = this.route.snapshot.queryParamMap.get('name') ?? '';
    this.slot.nativeElement.innerHTML = `<img src="/avatars/default.png" alt="${escapeHtml(name)}">`;
  }
}
