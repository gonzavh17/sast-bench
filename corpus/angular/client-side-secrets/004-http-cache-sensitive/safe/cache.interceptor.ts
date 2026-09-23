import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest, HttpResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, of } from 'rxjs';
import { tap } from 'rxjs/operators';

const CACHEABLE = ['/api/countries', '/api/currencies', '/api/plans'];

@Injectable()
export class CacheInterceptor implements HttpInterceptor {
  private readonly cache = new Map<string, HttpResponse<unknown>>();

  intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    const path = new URL(req.url, 'https://api.example.com').pathname;
    if (req.method !== 'GET' || !CACHEABLE.includes(path)) {
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
