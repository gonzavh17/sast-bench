# Prediccion client-side-secrets (escrita ANTES del corpus)

## Semgrep: 0/12, recall 0%, ruido 0%

Sin reglas aplicables en el pin (javascript+typescript). Las de secretos que hay
son de Express, passport, jsonwebtoken, HMAC, o exigen import de jwt-decode.
Confianza: muy alta. Es un cero por construccion del set, no por la herramienta.

## CodeQL: 7/12 aprox.

Queries en juego: js/clear-text-storage-of-sensitive-data, js/clear-text-logging,
js/hardcoded-credentials, js/sensitive-get-query, js/build-artifact-leak.
Todas identifican "dato sensible" por HEURISTICA DE NOMBRE (token, password,
secret, apiKey...), no por entropia del valor.

| caso | tema | prediccion | por que |
|---|---|---|---|
| 001 environment secret key | env | FN | js/hardcoded-credentials pide que el literal se USE como credencial en una API que la reciba; una const exportada no alcanza |
| 002 token en localStorage | storage | TP | clear-text-storage: caso de manual |
| 003 console.log con PII | logs | TP | clear-text-logging, si el campo se llama password/token; con email/dni es mas dudoso |
| 004 cache de peticiones | cache | FN | ninguna query modela un Map en memoria como almacenamiento |
| 005 servicio -> helper -> localStorage | storage | TP | taint interprocedural, es lo que CodeQL hace bien |
| 006 interceptor loguea el body | logs | TP | clear-text-logging con el password en el body |
| 007 apiKey en query string GET | env | TP | js/sensitive-get-query existe justo para esto |
| 008 logger helper con PII | logs | TP | clear-text-logging a traves del helper |
| 009 publishable vs secret key | decoy env | FN | mismo motivo que 001 |
| 010 console.debug vs isDevMode | decoy logs | TP vuln / riesgo FP en safe | la safe tambien loguea; si el campo parece sensible, dispara igual |
| 011 opaque id vs JWT | decoy storage | TP vuln / riesgo FP en safe | la safe guarda algo llamado token-ish; alta chance de FP |
| 012 cache allowlist rota | decoy cache | FN | mismo motivo que 004 |

Esperado: recall ~58% (7/12), 1-2 FP en los decoy 010/011, pair score ~5-6/12.

## codeql+llm: <= CodeQL en recall, mejor en ruido

ESTRUCTURAL: el filtro solo descarta, nunca agrega. No puede recuperar ningun FN
de CodeQL. Su unico efecto posible es bajar el ruido.
Prediccion: mata los FP de 010/011, no pierde ningun TP -> pair score sube a 7/12.

Riesgo del filtro en esta familia: los decoy 009/011 dependen de saber que una
pk_live_ es publicable por diseno y que un identificador opaco no sirve sin la
cookie. Es conocimiento de dominio, no razonamiento sobre el flujo. Menos seguro
que en XSS.
