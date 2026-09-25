import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable()
export class IdentityInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    const userId = localStorage.getItem('user_id');
    if (!userId) {
      return next.handle(req);
    }
    return next.handle(req.clone({ setHeaders: { 'X-User-Id': userId } }));
  }
}
