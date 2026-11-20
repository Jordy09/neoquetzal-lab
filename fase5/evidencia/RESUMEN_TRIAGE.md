# Fase 5 – Resumen de resultados y triage (Checkov)

Laboratorio NeoQuetzal · Entregable 3 · Herramienta: Checkov 3.4.5 (análisis estático, sin desplegar nada)
Archivos de evidencia: `checkov_<terraform|kubernetes|dockerfile>_<vulnerable|secure>.txt`

## 1. Resultado general (antes → después)

| Objetivo | Versión vulnerable | Versión corregida |
|---|---|---|
| Terraform AWS (28 recursos) | 48 aprobados · **86 fallidos** | 223 aprobados · **0 fallidos** · 15 excepciones documentadas |
| Kubernetes (Deployment EKS) | 69 aprobados · **21 fallidos** | 91 aprobados · **0 fallidos** · 1 excepción documentada |
| Dockerfile de la API | 43 aprobados · **5 fallidos** | 65 aprobados · **0 fallidos** |
| **Quality Gate** | **FAILED** (exit 1) | **SUCCESS** (exit 0) |

> La versión corregida tiene más controles "aprobados" porque agrega recursos de seguridad que antes no existían (flow logs, WAF, AWS Backup, KMS, logs de CloudWatch).

## 2. Triage de Terraform: 86 fallos → 10 causas raíz (de-duplicación)

| # | Causa raíz | Checks de Checkov (ejemplos) | Problema base / riesgo | Corrección en la versión segura |
|---|---|---|---|---|
| 1 | Bucket de documentos KYC público | CKV_AWS_53/54/55/56, CKV2_AWS_6 | CB-08 · R-03 (fuga KYC) | Public Access Block en los 4 buckets; política solo para el rol del servicio KYC y solo por TLS |
| 2 | Datos sin cifrado con llave propia | CKV_AWS_96, 327, 145, 136, 149, 58, 35; CKV_AWS_7 (sin rotación); CKV2_AWS_64 | Cifrado AES-256 en reposo (Fase 2) | Una llave KMS con rotación y política; Aurora, S3, ECR, Secrets Manager, secretos de EKS, CloudTrail y logs cifrados |
| 3 | Base de datos expuesta y usada con usuario administrador | CKV_AWS_17 (pública), 162 (sin autenticación IAM), 139, 226 | CB-06 · CB-09 | Subred privada, sin IP pública, autenticación IAM para la app, contraseña maestra gestionada por Secrets Manager, protección contra borrado |
| 4 | Red abierta | CKV_AWS_24 (SSH 0.0.0.0/0), CKV_AWS_382, CKV_AWS_130, CKV_AWS_23, CKV2_AWS_12 | Zero Trust / microsegmentación | Sin SSH (administración por SSM), SG de BD solo desde nodos EKS, subredes privadas, SG por defecto cerrado |
| 5 | IAM con privilegios totales y llaves de larga duración | CKV_AWS_62, 63, 286–290, 355, 40, 273; CKV2_AWS_40 | CB-09 · CB-10 · menor privilegio | GitHub Actions entra por OIDC (sin llaves), rol CI/CD solo con ECR y EKS, rol del servicio KYC solo con su bucket y su llave |
| 6 | Auditoría incompleta | CKV_AWS_67, 36, 252, 18, 324, 37, 76, 73; CKV2_AWS_10, 11, 27, 4 | CB-07 | CloudTrail multi-región con validación, cifrado, CloudWatch y SNS; eventos de datos del bucket KYC; VPC Flow Logs; logs de EKS, Aurora y API Gateway |
| 7 | Plano de control de EKS público | CKV_AWS_38, 39 | Perímetro cloud | Endpoint de EKS solo privado |
| 8 | Registro de imágenes inseguro | CKV_AWS_51 (tags mutables), 163 (sin escaneo) | Cadena de suministro | Tags inmutables y escaneo al subir la imagen |
| 9 | API sin WAF | CKV2_AWS_29 | R-02 (fuerza bruta) · OWASP API Top 10 | WAF regional con reglas OWASP, SQLi, entradas maliciosas (Log4j), IPs anónimas y límite de tasa en /auth/login; throttling en API Gateway |
| 10 | Resiliencia y operación | CKV_AWS_21, 313, 118, 353, 217, 237; CKV2_AWS_61, 8, 57 | Disponibilidad | Versionado, ciclo de vida, AWS Backup 35 días, monitoreo mejorado, rotación de secretos cada 30 días |

## 3. Excepciones documentadas (no son fallas ocultas)

| Check | Dónde | Decisión | Justificación |
|---|---|---|---|
| CKV_AWS_144 (replicación entre regiones) | 4 buckets | Riesgo aceptado, ticket SEC-E3-01 | Fuera del alcance del laboratorio; se planifica en el roadmap |
| CKV2_AWS_62 (notificaciones S3) | 4 buckets | No aplica | Las alertas salen de CloudTrail (eventos de datos) hacia el SIEM |
| CKV_AWS_120 y CKV_AWS_225 (cache del API Gateway) | Stage prod | No aplica | Las respuestas tienen saldos y datos personales: no deben quedar en caché |
| CKV2_AWS_51 (certificado de cliente) | Stage prod | No aplica | La app se autentica con OAuth2 + PKCE (Cognito); mTLS se usa entre API Gateway y EKS |
| CKV_AWS_18 (logs de acceso) | Bucket de logs | No aplica | Es el bucket destino de los logs; registrarse a sí mismo crea un ciclo |
| CKV_AWS_111, 356, 109 | Política de la llave KMS | **Falso positivo** | En una política de llave KMS el recurso `*` significa "esta llave"; es el patrón por defecto de AWS |
| CKV_K8S_35 (secreto como variable) | Deployment | Riesgo aceptado temporal, ticket SEC-E3-02 (vence 31-dic-2026) | La app lee la contraseña de una variable; control compensatorio: rotación cada 30 días y sistema de archivos de solo lectura |

## 4. Falsos negativos (lo que Checkov NO detectó)

Revisión manual del Terraform vulnerable:
- **PostgreSQL (5432) abierto a 0.0.0.0/0**: Checkov tiene reglas para 22, 3389 y 80, pero no avisó por el 5432.
- **Contraseña maestra en texto plano** (`master_password = "NeoQuetzal2026!"`): el escáner de secretos no la reconoció como secreto.
- **Secretos en variables ENV del Dockerfile** (`JWT_SECRET`, `CORE_API_KEY`): Checkov no los marcó.

Conclusión para el informe: la herramienta no reemplaza la revisión humana ("DAST/SAST no demuestran que algo sea seguro", clase del 9-nov). Por eso el pipeline combina Checkov con Trivy (escáner de secretos) y revisión de código.

## 5. Kubernetes (21 fallos → 5 causas raíz)

1. **Contenedor privilegiado y como root**: CKV_K8S_16, 20, 23, 40, 37, 28, 29, 22, 31 → `runAsNonRoot`, UID 10001, sin escalamiento, `drop: ALL`, sistema de archivos de solo lectura, seccomp.
2. **Imagen no fija**: CKV_K8S_14 (`latest`), 43 (sin digest) → imagen de ECR por digest.
3. **Sin límites ni probes**: CKV_K8S_10–13, 8, 9 → requests/limits y probes.
4. **Namespace por defecto y token montado**: CKV_K8S_21, 38 → namespace propio, ServiceAccount con IRSA, sin token.
5. **Sin microsegmentación**: CKV2_K8S_6 → NetworkPolicy; además el Service pasó de LoadBalancer público a ClusterIP (entra solo por API Gateway + WAF).

## 6. Dockerfile (5 fallos)

CKV_DOCKER_1 (puerto 22), CKV_DOCKER_2 (sin HEALTHCHECK), CKV_DOCKER_3 (sin usuario, corre como root), CKV_DOCKER_4 (ADD en vez de COPY), CKV2_DOCKER_1 (sudo).
Corrección: imagen `node:22-alpine` multi-etapa, solo dependencias de producción, `USER node`, HEALTHCHECK, sin herramientas extra ni secretos.

## 7. Trivy (imagen)

**Pendiente:** se genera al correr el workflow en GitHub Actions (artefactos `trivy-vulnerable` y `trivy-secure`, más la tabla en el Summary). Se espera:
- Vulnerable (`node:22.1.0-bullseye`): cientos de CVE del sistema operativo, varios CRITICAL/HIGH con parche → gate **FAILED**.
- Corregida (`node:22-alpine` + `apk upgrade`): pocas o ninguna CRITICAL/HIGH con parche → gate **SUCCESS**.
