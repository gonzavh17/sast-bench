import { AfterViewInit, Component, ElementRef, Renderer2, ViewChild } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-banner',
  templateUrl: './banner.component.html',
})
export class BannerComponent implements AfterViewInit {
  @ViewChild('banner', { static: true }) banner!: ElementRef<HTMLDivElement>;

  constructor(
    private route: ActivatedRoute,
    private renderer: Renderer2,
  ) {}

  ngAfterViewInit(): void {
    const message = this.route.snapshot.queryParamMap.get('message') ?? '';
    this.renderer.setProperty(this.banner.nativeElement, 'textContent', message);
  }
}
