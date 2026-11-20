# Guía para Pedro — Pentest Caja Negra + Perímetro (Entregable 2, Fase 4)

Hola Pedro. Tu parte es el **ataque desde afuera**, como lo haría alguien que no
conoce el sistema ni tiene credenciales: escaneás el servicio, revisás qué puertas
quedan abiertas y mapeás el perímetro. Las herramientas típicas son **OWASP ZAP**
(escáner web) y **Nmap** (escáner de puertos).

---

## Qué te toca entregar

Un Word (`E2_CajaNegra_Citalan.docx`, Arial 12, 1.5, APA) con:

1. **Escaneo externo:** qué herramienta usaste y los hallazgos (cabeceras faltantes,
   tecnología expuesta, rutas accesibles).
2. **Mapa del perímetro:** tabla de endpoints, puertos y servicios expuestos.
3. Capturas de ZAP y/o Nmap como evidencia.
4. Cada hallazgo ligado a su amenaza T-xx / riesgo R-xx y al requisito RS-xx.

---

## Opción A — Usar la evidencia ya generada (lo más rápido)

En `evidencia/evidencia_fase4_cajanegra.txt` está el escaneo real de las cabeceras
HTTP del servicio y la lista de hallazgos. Tomás captura y lo pasás a tu documento.

## Opción B — Correrlo vos mismo

Primero levantás la app (o pedí que alguien la tenga corriendo):
```
cd vulnerable
npm install
node --experimental-sqlite db.js
node --experimental-sqlite app.js      # queda en http://localhost:3000
```

**Con Nmap (puertos y servicios):**
```
nmap -sV -p 1-4000 localhost
```
Vas a ver el puerto 3000 abierto con un servicio HTTP (Node/Express).

**Con OWASP ZAP (escáner web, el que pide la rúbrica):**
1. Descargá ZAP (gratis): https://www.zaproxy.org/download/
2. Abrí ZAP → "Automated Scan" → URL: `http://localhost:3000` → Attack.
3. Cuando termine, mirá la pestaña **Alerts**. Vas a encontrar, entre otras:
   - Ausencia de cabeceras de seguridad (CSP, HSTS, X-Content-Type-Options…).
   - Posible exposición de la tecnología del servidor (X-Powered-By).
4. Exportá el reporte (Report → Generate HTML Report) y tomá capturas.

---

## Mapa del perímetro (para tu documento)

| Ruta / Puerto | Método | ¿Requiere token? | Observación |
|---|---|---|---|
| Puerto 3000/tcp | — | — | Servicio HTTP en texto plano (sin TLS) — CB-02, T-04 |
| `/` | GET | No | Revela nombre y versión del servicio |
| `/api/login` | POST | No | Punto de fuerza bruta e inyección SQL |
| `/api/accounts/:id` | GET | Sí | Expuesto a BOLA (lo prueba Edgar) |
| `/api/accounts/:id/movements` | GET | Sí | Exfiltración por paginación |
| `/api/transfers` | POST | Sí | Transferencia sin validar dueño |
| `/api/clientes` | GET | Sí | Lista todos los clientes con DPI |

## Hallazgos de caja negra y su corrección

| Hallazgo | Amenaza / Riesgo | RS que lo corrige |
|---|---|---|
| Sin cabeceras de seguridad (CSP, HSTS, nosniff, X-Frame-Options) | T-20 | RS-15 |
| Servicio en HTTP sin TLS | T-04 / R-07 | RS-05 |
| Tecnología del servidor expuesta (X-Powered-By) | T-05 relac. | RS-15 |
| Endpoints sensibles alcanzables desde internet | T-12 / R-10 | RS-12 |

En la versión corregida (`secure/`), al escanearla las cabeceras de seguridad ya
aparecen (gracias a helmet). Si podés, mostrá el contraste: suma puntos.

Cualquier duda me decís. — Jordy
