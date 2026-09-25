# Prediccion broken-authorization (escrita y commiteada ANTES de correr)

## Semgrep: 0/12, sin ruido

Las unicas reglas cercanas del pin son de JWT y exigen una libreria:
`jwt-decode-without-verify` (jsonwebtoken) y `react-jwt-decoded-property`
(import de jwt-decode). Los casos 006 y 011 decodifican con `atob`, sin
libreria. No hay nada sobre guards, roles ni ids de la URL.
Confianza: muy alta. Como en secretos, es un cero por construccion del set.

## CodeQL: 0/12, sin ruido

Queries candidatas en javascript-security-extended, y por que no deberian
disparar:

| query | por que no |
|---|---|
| `js/user-controlled-bypass` (CWE-807) | pide un `if` sobre un valor del usuario que proteja una "accion sensible", que para CodeQL es una llamada con nombre tipo login/auth/verify. Ningun caso tiene eso: los guards devuelven un booleano y el branch llama a `http.get`/`post` |
| `js/jwt-missing-verification` (CWE-347) | solo modela `jsonwebtoken.verify(..., false)` |
| `js/client-side-request-forgery` (CWE-918) | es la unica con chance: el id de la URL llega a la URL del request en 003, 008, 010 (las dos variantes) y 012. Pero un prefijo como `/api/users/` cuenta como sanitizador (UrlConcatenation.qll: una `/` inicial fija el host, lo que sigue es path). Confianza media |

Si `js/client-side-request-forgery` dispara igual, queda **sin mapear**: es
CWE-918, habla de que un atacante elija a donde va el request, no de quien
decide la autorizacion. Aparece como ruido en el reporte y se discute aparte,
en vez de regalarle un TP.

## codeql+ext: igual que CodeQL

La extension solo toca storage y logging de credenciales. 006, 009 y 011 leen
`id_token` / escriben `me_role`, pero una lectura no es un sink y `me_role` no
matchea la regex.

## codeql+llm: 0 llamadas

Sin hallazgos que revisar, el filtro no hace nada. Mismo resultado estructural
que en secretos.

## La lectura que importa

Si da 0/12 para todos, la familia muestra lo esperable: las herramientas de
reglas buscan flujos de dato peligroso hacia un sink, y aca el problema es
*donde vive la autoridad*, algo que no tiene sink. Es el terreno donde un LLM
solo tendria que diferenciarse, y el motivo para correr ese brazo despues.
