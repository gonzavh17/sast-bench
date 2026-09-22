import { AfterViewInit, Component, ElementRef, ViewChild } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-changelog',
  templateUrl: './changelog.component.html',
})
export class ChangelogComponent implements AfterViewInit {
  @ViewChild('entries', { static: true }) entries!: ElementRef<HTMLDivElement>;

  constructor(private route: ActivatedRoute) {}

  ngAfterViewInit(): void {
    const entry = this.route.snapshot.queryParamMap.get('entry') ?? '';
    this.entries.nativeElement.insertAdjacentText('beforeend', entry);
  }
}
