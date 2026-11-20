# Guía para Gio — SAST + SCA (Entregable 2, Fase 3)

Hola Gio. Tu parte es el **análisis del código y de las dependencias** de la app
NeoQuetzal-lab (la mini-app de banca que armamos con los fallos del Entregable 1).
Son dos herramientas: **SAST** (revisa el código) y **SCA** (revisa las librerías).

No necesitás que la app esté corriendo: estas herramientas solo leen archivos.

---

## Qué te toca entregar

Un documento Word (`E2_SAST_SCA_Chiche.docx`, Arial 12, 1.5, APA como el E1) con:

1. **Sección SAST:** qué es, qué herramienta usaste (Semgrep) y una **tabla de hallazgos**.
2. **Sección SCA:** qué es, qué herramienta usaste (npm audit / Dependency-Check) y una **tabla de CVEs**.
3. **Codificación segura:** 2 o 3 ejemplos de "antes y después" (código vulnerable vs. corregido).
4. Capturas de pantalla de las herramientas como evidencia (Figura 1, 2, …).

**Regla de oro:** cada hallazgo se conecta con su amenaza (T-xx), su problema base
(CB-xx) y el requisito que lo corrige (RS-xx). Las tablas de abajo ya lo traen hecho.

---

## Opción A — Usar la evidencia ya generada (lo más rápido)

En la carpeta `evidencia/` ya están los reportes reales que corrí yo:

- `evidencia_fase3_SAST_semgrep.txt` — resultado de Semgrep sobre el código.
- `evidencia_fase3_SCA_npm-audit.txt` — resultado de npm audit (10 vulnerabilidades).

Abrís esos archivos, tomás captura y los resumís en tus tablas. Listo.

## Opción B — Correrlo vos mismo (si querés la captura propia)

Necesitás tener instalado Node y Python. En una terminal, dentro de la carpeta del lab:

**SAST con Semgrep:**
```
pip install semgrep
semgrep --config p/security-audit --config p/javascript ./vulnerable
```

**SCA con npm audit:**
```
cd vulnerable
npm install
npm audit
```

(Opcional, si tenés Docker, OWASP Dependency-Check da un reporte HTML más vistoso;
en la guía de Jordy está cómo el pipeline lo genera solo.)

---

## Tabla de hallazgos SAST (para tu documento)

| # | Hallazgo (archivo) | Descripción | CB / T | Requisito RS |
|---|---|---|---|---|
| 1 | `config.js` | Secretos y API keys escritos en el código | CB-03, CB-09 / T-05, T-13 | RS-06 |
| 2 | `app.js` login | Consulta SQL armada por concatenación (SQLi) | CB-06 / T-09 | RS-08 |
| 3 | `app.js` | Secreto JWT débil y hardcodeado | CB-01 / T-01, T-02 | RS-04, RS-07 |
| 4 | `app.js` /accounts/:id | No verifica propiedad del recurso (BOLA) | CB-04 / T-06, T-07 | RS-01 |
| 5 | `app.js` login (catch) | El error devuelve la consulta SQL interna | — / T-17 | RS-11 |

## Tabla de hallazgos SCA (dependencias con CVE)

| Librería | Versión | Severidad | Problema principal | RS |
|---|---|---|---|---|
| lodash | 4.17.4 | **Crítica** | Prototype pollution / inyección de comandos | RS-13 |
| jsonwebtoken | 8.5.1 | Alta | Bypass de validación de firma | RS-13 |
| axios | 0.21.1 | Alta | SSRF / ReDoS | RS-13 |
| body-parser / qs | 1.19.0 | Alta | Denegación de servicio (DoS) | RS-13 |

Total: **10 vulnerabilidades (1 crítica, 6 altas, 3 bajas).**

---

## Codificación segura — ejemplos "antes y después"

**1. Inyección SQL (login)**
- Antes (`vulnerable/app.js`): la consulta se arma pegando texto del usuario.
- Después (`secure/app.js`): consulta **parametrizada** con `?`, inmune a SQLi.

**2. Secretos en el código**
- Antes (`vulnerable/config.js`): `JWT_SECRET = "neoquetzal123"`.
- Después (`secure/config.js`): `JWT_SECRET = process.env.JWT_SECRET` (variable de entorno).

**3. Manejo de token JWT**
- Antes: token de 24h firmado con secreto débil.
- Después: token de 15 min, secreto fuerte, y la app no arranca si falta el secreto.

Podés comparar los dos archivos lado a lado (`vulnerable/` vs `secure/`) para tus capturas.

Cualquier duda me escribís. — Jordy
