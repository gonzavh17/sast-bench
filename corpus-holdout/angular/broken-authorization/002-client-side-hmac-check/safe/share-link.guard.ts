import { HttpClient } from '@angular/common/http';
import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

export const shareLinkGuard: CanActivateFn = (route) => {
  const docId = route.paramMap.get('docId') ?? '';
  const signature = route.queryParamMap.get('sig') ?? '';
  return inject(HttpClient)
    .get<{ valid: boolean }>('/api/share/verify', { params: { docId, sig: signature } })
    .pipe(
      map((result) => result.valid),
      catchError(() => of(false)),
    );
};
