import { AfterViewInit, Component, ElementRef, ViewChild } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-note',
  templateUrl: './note.component.html',
})
export class NoteComponent implements AfterViewInit {
  @ViewChild('noteBox', { static: true }) noteBox!: ElementRef<HTMLDivElement>;

  constructor(private route: ActivatedRoute) {}

  ngAfterViewInit(): void {
    const note = this.route.snapshot.queryParamMap.get('note') ?? '';
    this.noteBox.nativeElement.innerHTML = note;
  }
}
