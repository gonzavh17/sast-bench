/**
 * Session credential names that CodeQL's heuristic does not consider
 * sensitive.
 *
 * `SensitiveDataHeuristics.qll` (codeql/concepts 0.0.32) covers `password`,
 * `secret`, `apiKey`, `oauth`, `authKey`, but not `accessToken`, `jwt` or
 * `bearer`: exactly what an SPA stores after login. This extension adds those
 * names as a source for the family's two queries.
 *
 * Bare `token` is not added: it matches `csrfToken`, `nextPageToken`,
 * `CancellationToken` or a tokenizer. What each variant costs is measured
 * separately, on real repos.
 */

import javascript
import semmle.javascript.security.SensitiveActions
import semmle.javascript.security.dataflow.CleartextLoggingCustomizations
private import codeql.concepts.internal.SensitiveDataHeuristics

/** Holds if `name` looks like a session credential. */
bindingset[name]
predicate isSessionCredentialName(string name) {
  name.regexpMatch("(?i).*((access|refresh|id|auth|session|bearer).?token|jwt|bearer).*") and
  // Reuse CodeQL's exclusions: hash, encrypt, url, path, etc.
  not name.regexpMatch(HeuristicNames::notSensitiveRegexp())
}

/** A variable or property read whose name indicates a session credential. */
class SessionCredentialAccess extends DataFlow::Node {
  string name;

  SessionCredentialAccess() {
    (
      this.asExpr().(VarAccess).getName() = name
      or
      this.(DataFlow::PropRead).getPropertyName() = name
    ) and
    isSessionCredentialName(name)
  }

  string getName() { result = name }
}

/** Source for `clear-text-storage`: extends what CodeQL considers sensitive. */
class SessionCredentialNode extends SensitiveNode instanceof SessionCredentialAccess {
  override string describe() { result = "an access to " + super.getName() }

  override SensitiveDataClassification getClassification() {
    result = SensitiveDataClassification::password()
  }
}

/** Source for `clear-text-logging`, which has its own sources apart from `SensitiveNode`. */
class SessionCredentialLogSource extends CleartextLogging::Source instanceof SessionCredentialAccess
{
  override string describe() { result = "an access to " + super.getName() }
}
