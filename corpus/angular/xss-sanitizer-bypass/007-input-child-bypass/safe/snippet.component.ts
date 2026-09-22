import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-snippet',
  templateUrl: './snippet.component.html',
})
export class SnippetComponent {
  @Input() html = '';
}
