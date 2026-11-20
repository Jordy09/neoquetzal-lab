# NeoQuetzal-lab – Fase 5 (Entregable 3): IaC Hardening y escaneo de contenedores

Esta carpeta se agrega al laboratorio `neoquetzal-lab` del Entregable 2.

```
fase5/
├── infra/vulnerable/main.tf     Terraform AWS con los fallos (CB-06, 07, 08, 09, 10)
├── infra/secure/main.tf         Terraform corregido (cifrado KMS, red privada, IAM mínimo, auditoría, WAF)
├── docker/Dockerfile.vulnerable Imagen vieja, root, secretos, herramientas de más
├── docker/Dockerfile.secure     Alpine multi-etapa, usuario sin privilegios, HEALTHCHECK
├── k8s/vulnerable/              Deployment privilegiado, root, LoadBalancer público
├── k8s/secure/                  Deployment endurecido + NetworkPolicy + IRSA
└── evidencia/                   Resultados reales de Checkov + RESUMEN_TRIAGE.md
.github/workflows/fase5-iac-contenedores.yml   Pipeline: Checkov + Trivy + SBOM + Quality Gate
```

> Académico: nada de esto se despliega en AWS. Solo se analiza con herramientas estáticas.

## Correr el pipeline en GitHub (FAILED → SUCCESS)

1. Subir a GitHub todo el contenido del laboratorio (carpetas `vulnerable/`, `secure/`, `fase5/` y `.github/`).
2. El push corre el workflow con la versión **vulnerable** → debe quedar **FAILED**. Tomar captura del Summary (tablas de Trivy y del Quality Gate) y de los logs de Checkov.
3. Ir a **Actions → Fase 5 - IaC y Contenedores → Run workflow → version: secure** → debe quedar **SUCCESS**. Tomar las mismas capturas.
4. Descargar los artefactos (`checkov-*`, `trivy-*`) para el informe.

> Si el navegador traduce GitHub, desactivar la traducción (los nombres de carpetas se confunden).

## Correr Checkov en la computadora (opcional)

```
pip install checkov
checkov -d fase5/infra/vulnerable --framework terraform --compact
checkov -d fase5/infra/secure --framework terraform --compact
```
