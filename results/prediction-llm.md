# Prediction: LLM-only arms (written and committed BEFORE the run)

Model `claude-opus-5`, default effort, one run per cell. 36 pairs per arm.

## The bet in one line

The model finds much more than Semgrep and CodeQL, **and flags a lot of safe
twins**. Recall goes up, the pair score goes up much less, and on authorization
the false alarms eat most of the gain.

## Blind arm

| family | recall | safe twins flagged | pair score | why |
|---|---|---|---|---|
| xss-sanitizer-bypass | ~11/12 | ~3/12 | ~8/12 | XSS is the best-known pattern there is. The risk is on the safe side of the decoys: 010, 011 and 012 still call `bypassSecurityTrustHtml`, on a sanitized value. A reviewer that sees `bypassSecurityTrust*` tends to flag it anyway |
| client-side-secrets | ~10/12 | ~3/12 | ~7/12 | Tokens in storage, PII in logs and the `sk_live_` key are textbook. 004/012 (in-memory cache) is the most likely miss. Likely false alarms: 011 safe (a token-derived value in sessionStorage) and "defense in depth" remarks on safe twins that still handle a token |
| broken-authorization | ~10/12 | ~6/12 | ~4/12 | The vulnerable side is easy to explain ("a client-side check can be bypassed"). The trouble is that the same sentence is true of every safe twin that has a guard: 001, 005, 006, 009 and 011 safe all still decide something in the browser |

**Blind total: ~19/36 pairs.** For reference, CodeQL alone is 11/36.

## Guided arm

Same code, with the three families described. It should find a little more
and flag more: naming the families primes the model to look for them.
Expected recall ~33/36, false alarms ~15/36, **pair score about the same as
blind or a bit lower (~17/36)**.

## What would falsify the bet

- If the pair score on authorization is 8/12 or more, the model reads *where
  the authority lives* and not just "there is a guard". That would be the most
  interesting outcome.
- If the safe twins are flagged in fewer than 4 of 36 pairs in the blind arm,
  the "LLMs are noisy" part of the bet is wrong.

## Mapping notes

- Blind findings are mapped by CWE with `scoring/rule_map/llm-blind.yaml`,
  written before this run. A CWE outside it (CSRF, CWE-352, is the most
  likely one) is noise, not a false alarm, the same as an unmapped rule of a
  rule-based tool.
- Guided findings tagged `other` are noise too.
