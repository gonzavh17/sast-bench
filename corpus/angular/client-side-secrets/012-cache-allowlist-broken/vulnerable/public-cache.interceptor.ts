import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest, HttpResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, of } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class PublicCacheInterceptor implements HttpInterceptor {
  private readonly cache = new Map<string, HttpResponse<unknown>>();

  private isPublic(url: string): boolean {
    return url.includes('/public/');
  }

  intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    if (req.method !== 'GET' || !this.isPublic(req.url)) {
      return next.handle(req);
    }
    const hit = this.cache.get(req.urlWithParams);
    if (hit) {
      return of(hit.clone());
    }
    return next.handle(req).pipe(
      tap((event) => {
        if (event instanceof HttpResponse) {
          this.cache.set(req.urlWithParams, event.clone());
        }
      }),
    );
  }
}
