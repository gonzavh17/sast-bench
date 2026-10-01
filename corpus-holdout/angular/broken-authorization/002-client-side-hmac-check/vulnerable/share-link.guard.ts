import { CanActivateFn } from '@angular/router';

import { environment } from './environment';
import { hmacHex } from './hmac';

export const shareLinkGuard: CanActivateFn = async (route) => {
  const docId = route.paramMap.get('docId') ?? '';
  const signature = route.queryParamMap.get('sig') ?? '';
  const expected = await hmacHex(environment.shareSigningKey, docId);
  return signature === expected;
};
