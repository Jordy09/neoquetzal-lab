# NeoQuetzal-lab — Laboratorio del Entregable 2

Curso: Seguridad en Aplicaciones · Maestría en Seguridad Informática (UMG)
Grupo: Jordy Castillo, Pedro Citalán, Edgar Ba Artola, Edgar (Gio) Chiché

Este laboratorio es una **mini aplicación de banca (API) creada a propósito con
fallos** para poder ejecutar las pruebas que pide el Entregable 2 (Fase 3 DevSecOps y
Fase 4 Ciberdefensa). Reproduce los problemas CB-01 a CB-10 descritos en el Entregable 1.

> Es un ejercicio académico. NO usar en producción ni exponer a internet.

## Contenido

```
neoquetzal-lab/
├── vulnerable/        App con los fallos (lo que se analiza y se ataca)
├── secure/            Misma app corregida (para el "antes y después")
├── .github/workflows/ Pipeline DevSecOps (SAST + secretos + SCA)
├── semgrep-rules.yml  Reglas de SAST locales (funcionan sin internet)
├── evidencia/         Reportes YA generados (se pueden usar tal cual)
│   ├── evidencia_fase3_SAST_semgrep.txt
│   ├── evidencia_fase3_SCA_npm-audit.txt
│   ├── evidencia_fase4_ataques.txt
│   ├── evidencia_fase4_cajanegra.txt
│   └── evidencia_despues_corregida.txt
└── guias/             Una guía por integrante
```

## Cómo correr la app (opcional — la evidencia ya está generada)

Requiere Node 22 o superior.

```
cd vulnerable
npm install
node --experimental-sqlite db.js     # crea la base con datos de prueba
node --experimental-sqlite app.js     # API en http://localhost:3000
```

La versión corregida es igual, pero necesita un secreto por variable de entorno:
```
cd secure
npm install
node --experimental-sqlite db.js
JWT_SECRET=un_secreto_largo node --experimental-sqlite app.js   # puerto 3000
```

## Usuarios de prueba

| Usuario | Contraseña | Cuenta | Saldo |
|---|---|---|---|
| jperez | Pollo123 | 101 | Q15,230.50 |
| mlopez | Flores456 | 102 y 104 | Q48,900 y Q1,200,000 |
| crodas | Quetzal789 | 103 | Q2,750.75 |

## Resumen de hallazgos (todos trazables al Entregable 1)

| Área | Hallazgo | CB / T | RS |
|---|---|---|---|
| SAST | Secretos hardcodeados | CB-03, CB-09 / T-05, T-13 | RS-06 |
| SAST | Inyección SQL por concatenación | CB-06 / T-09 | RS-08 |
| SAST | Error que filtra datos internos | T-17 | RS-11 |
| SCA | 10 dependencias vulnerables (1 crítica) | — | RS-13 |
| Ciberdefensa | BOLA/IDOR en cuentas y transferencias | CB-04 / T-06, T-07 | RS-01 |
| Ciberdefensa | Login sin límite de intentos | CB-05 / T-03 | RS-03 |
| Caja negra | Sin cabeceras de seguridad, sin TLS | CB-02 / T-04, T-20 | RS-05, RS-15 |


## Entregable 3 – Fase 5 (IaC y contenedores)

La carpeta `fase5/` contiene el Terraform de AWS, el Dockerfile y los manifiestos de Kubernetes
en versión vulnerable y endurecida, y el workflow `.github/workflows/fase5-iac-contenedores.yml`
(Checkov + Trivy + SBOM + Quality Gate). Ver `fase5/README.md`.

En el Entregable 3 se actualizaron las dependencias de `secure/` (express 4.22.3, lodash 4.18.1,
body-parser 1.20.9, jsonwebtoken 9.0.3) por avisos publicados después del Entregable 2, y se agregó
`secure/package-lock.json`. El workflow del Entregable 2 (`devsecops.yml`) quedó de ejecución manual.
