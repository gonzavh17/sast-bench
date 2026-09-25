# Prediccion codeql+ext sobre client-side-secrets (escrita ANTES de correrla)

## Que cambia

Una extension de 1 archivo QL (`runners/codeql-ext/`) que suma nombres de
credenciales de sesion a lo que CodeQL considera sensible:
`access_token`, `refreshToken`, `idToken`, `authToken`, `sessionToken`,
`bearerToken`, `jwt`. Solo toca las dos queries de la familia
(`js/clear-text-storage-of-sensitive-data` y `js/clear-text-logging`); el resto
de `javascript-security-extended` corre igual.

No se agrega `token` a secas: pega con `csrfToken`, `nextPageToken`,
`CancellationToken`, tokenizers. Medir ese costo es el paso 3.

## Correccion al commit c0e7c10

Decia que la heuristica no tiene `apiKey`. Si lo tiene: `maybePassword()`
incluye `api.?(key|tok)`. Lo que falta es `token` / `jwt` / `bearer`.

ng-sec-007 no fallo por el nombre: `js/sensitive-get-query` solo modela rutas
de servidor (`Routing::RouteSetup` + `Http::RequestInputAccess`, o sea Express
leyendo `req.query`). Un `HttpClient.get` de Angular armando la URL no es su
caso, con cualquier nombre.

## Prediccion por caso

| caso | vuln | safe | por que |
|---|---|---|---|
| 001 secret en environment | FN | TN | no es storage ni logging; `js/hardcoded-credentials` esta fuera de la suite |
| 002 token en localStorage | **TP** | TN | `response.accessToken` -> `localStorage.setItem`: el caso exacto que faltaba |
| 003 console.log de PII | FN | TN | se loguea el objeto entero; ninguna lectura de propiedad con nombre sensible |
| 004 cache en Map | FN | TN | un Map en memoria no es un sink de storage |
| 005 servicio -> helper -> localStorage | **TP** | TN | mismo source que 002, taint entre archivos |
| 006 interceptor loguea el body | FN | TN | el password viaja por `HttpClient` al interceptor: ese salto es interno del framework y CodeQL no lo modela. No es un problema de nombre |
| 007 apiKey en query GET | FN | TN | query de servidor, ver arriba |
| 008 logger helper con PII | FN | TN | objeto entero, `creditCardNumber` solo aparece en el tipo |
| 009 publishable vs secret | FN | TN | como 001 |
| 010 console.debug de la sesion | FN | TN | loguea `session` entero, nunca lee `.accessToken` |
| 011 JWT vs referencia opaca | **TP** | **FP** | `sessionToken` -> `sessionStorage`. La safe guarda `sessionToken.slice(0, 8)`: el taint pasa por `slice` y el nombre sigue siendo el mismo. Una heuristica de nombres no puede leer este decoy |
| 012 allowlist rota | FN | TN | como 004 |

**Esperado: recall 3/12, FP 1/12, pair score 2/12** (002 y 005).

## La lectura que importa

El nombre explica a lo sumo 3 de los 12 casos. Los otros 9 no se arreglan con
una regex: son limites de modelado (flujo a traves de `HttpClient`, objetos
logueados enteros, secretos que viajan en el bundle, cache en memoria, query de
servidor usada en cliente). Si la corrida da esto, el hallazgo del 0/12 se
parte en dos: una parte barata de arreglar y otra que no.

Confianza: alta en 002/005/011-vuln, media en el FP de 011-safe (depende de que
`slice` propague taint en esta query, que deberia).
