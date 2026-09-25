/**
 * Nombres de credenciales de sesion que la heuristica de CodeQL no considera
 * sensibles.
 *
 * `SensitiveDataHeuristics.qll` (codeql/concepts 0.0.32) cubre `password`,
 * `secret`, `apiKey`, `oauth`, `authKey`, pero no `accessToken`, `jwt` ni
 * `bearer`: justo lo que una SPA guarda despues del login. Esta extension suma
 * esos nombres como fuente para las dos queries de la familia.
 *
 * No se agrega `token` a secas: pega con `csrfToken`, `nextPageToken`,
 * `CancellationToken` o un tokenizer. Cuanto cuesta cada variante se mide
 * aparte, sobre repos reales.
 */

import javascript
import semmle.javascript.security.SensitiveActions
import semmle.javascript.security.dataflow.CleartextLoggingCustomizations
private import codeql.concepts.internal.SensitiveDataHeuristics

/** Holds si `name` parece una credencial de sesion. */
bindingset[name]
predicate isSessionCredentialName(string name) {
  name.regexpMatch("(?i).*((access|refresh|id|auth|session|bearer).?token|jwt|bearer).*") and
  // Reusa las exclusiones de CodeQL: hash, encrypt, url, path, etc.
  not name.regexpMatch(HeuristicNames::notSensitiveRegexp())
}

/** Una lectura de variable o propiedad cuyo nombre indica una credencial de sesion. */
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

/** Fuente de `clear-text-storage`: extiende lo que CodeQL considera sensible. */
class SessionCredentialNode extends SensitiveNode instanceof SessionCredentialAccess {
  override string describe() { result = "an access to " + super.getName() }

  override SensitiveDataClassification getClassification() {
    result = SensitiveDataClassification::password()
  }
}

/** Fuente de `clear-text-logging`, que tiene sus propias fuentes aparte de `SensitiveNode`. */
class SessionCredentialLogSource extends CleartextLogging::Source instanceof SessionCredentialAccess
{
  override string describe() { result = "an access to " + super.getName() }
}
