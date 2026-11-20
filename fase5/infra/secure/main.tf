# =====================================================================
# NeoQuetzal - Infraestructura AWS (VERSION CORREGIDA / HARDENING)
# Laboratorio academico - Entregable 3, Fase 5 (IaC Hardening)
# Cada correccion indica el problema base (CB-xx) y el requisito (RS-xx).
# Las excepciones aceptadas usan "checkov:skip" con justificacion.
# =====================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "actual" {}

locals {
  cuenta = data.aws_caller_identity.actual.account_id
}

# ---------------------------------------------------------------------
# Llaves KMS (RS: cifrado AES-256 con llaves propias y rotacion)
# ---------------------------------------------------------------------
data "aws_iam_policy_document" "kms" {
  # Falsos positivos: en una key policy de KMS el recurso "*" se refiere unicamente a la propia llave,
  # y el principal es la cuenta (patron por defecto documentado por AWS).
  # checkov:skip=CKV_AWS_111:Falso positivo - key policy de KMS, "*" = esta llave.
  # checkov:skip=CKV_AWS_356:Falso positivo - key policy de KMS, "*" = esta llave.
  # checkov:skip=CKV_AWS_109:Falso positivo - key policy de KMS, administracion delegada a IAM de la cuenta.
  statement {
    sid       = "AdministracionCuenta"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"] # en una key policy "*" significa "esta llave"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.cuenta}:root"]
    }
  }
  statement {
    sid       = "CloudTrailCifrado"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com", "logs.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "datos" {
  description             = "Llave de datos NeoQuetzal (Aurora, S3, secretos, EKS)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

# ---------------------------------------------------------------------
# Red: subredes privadas, sin IP publica, flow logs (Zero Trust)
# ---------------------------------------------------------------------
resource "aws_vpc" "neoquetzal" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "neoquetzal-vpc" }
}

# El SG por defecto de la VPC no permite trafico
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.neoquetzal.id
}

resource "aws_subnet" "privada_a" {
  vpc_id                  = aws_vpc.neoquetzal.id
  cidr_block              = "10.20.11.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "privada_b" {
  vpc_id                  = aws_vpc.neoquetzal.id
  cidr_block              = "10.20.12.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/neoquetzal/vpc-flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.datos.arn
}

resource "aws_iam_role" "flow_logs" {
  name = "neoquetzal-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "escribir-flow-logs"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id          = aws_vpc.neoquetzal.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
}

# SG de los nodos EKS (microservicios): solo trafico interno de la VPC
resource "aws_security_group" "eks_nodos" {
  name        = "neoquetzal-eks-nodos"
  description = "Nodos EKS de microservicios - solo trafico interno"
  vpc_id      = aws_vpc.neoquetzal.id

  ingress {
    description = "HTTPS interno desde la VPC (VPC Link del API Gateway)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.neoquetzal.cidr_block]
  }

  egress {
    description = "HTTPS saliente solo dentro de la VPC (VPC endpoints)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.neoquetzal.cidr_block]
  }
}

# SG de la base de datos: solo desde los nodos EKS. SSH eliminado (se usa SSM).
resource "aws_security_group" "db" {
  name        = "neoquetzal-db"
  description = "Aurora PostgreSQL - solo desde nodos EKS"
  vpc_id      = aws_vpc.neoquetzal.id

  ingress {
    description     = "PostgreSQL desde microservicios"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodos.id]
  }

  egress {
    description = "Respuestas dentro de la VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.neoquetzal.cidr_block]
  }
}

# ---------------------------------------------------------------------
# S3: bucket de logs de acceso
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "logs_acceso" {
  # checkov:skip=CKV_AWS_18:Es el bucket destino de los logs de acceso; registrarse a si mismo genera un ciclo.
  # checkov:skip=CKV_AWS_144:Replicacion entre regiones fuera de alcance del laboratorio (riesgo aceptado, ticket SEC-E3-01).
  # checkov:skip=CKV2_AWS_62:No se requieren notificaciones de eventos para logs.
  bucket = "neoquetzal-logs-acceso"
}

# ---------------------------------------------------------------------
# S3: documentos KYC (CB-08 -> RS de cifrado y menor privilegio)
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "kyc" {
  # checkov:skip=CKV_AWS_144:Replicacion entre regiones fuera de alcance del laboratorio (riesgo aceptado, ticket SEC-E3-01).
  # checkov:skip=CKV2_AWS_62:Las alertas de acceso se generan desde CloudTrail data events y el SIEM, no con notificaciones S3.
  bucket = "neoquetzal-kyc-documentos"
}

resource "aws_s3_bucket" "estados_cuenta" {
  # checkov:skip=CKV_AWS_144:Replicacion entre regiones fuera de alcance del laboratorio (riesgo aceptado, ticket SEC-E3-01).
  # checkov:skip=CKV2_AWS_62:Las alertas de acceso se generan desde CloudTrail data events y el SIEM.
  bucket = "neoquetzal-estados-cuenta"
}

resource "aws_s3_bucket" "cloudtrail" {
  # checkov:skip=CKV_AWS_144:Replicacion entre regiones fuera de alcance del laboratorio (riesgo aceptado, ticket SEC-E3-01).
  # checkov:skip=CKV2_AWS_62:No se requieren notificaciones de eventos para el bucket de auditoria.
  bucket = "neoquetzal-cloudtrail-logs"
}

locals {
  buckets = {
    logs_acceso    = aws_s3_bucket.logs_acceso.id
    kyc            = aws_s3_bucket.kyc.id
    estados_cuenta = aws_s3_bucket.estados_cuenta.id
    cloudtrail     = aws_s3_bucket.cloudtrail.id
  }
}

resource "aws_s3_bucket_public_access_block" "todos" {
  for_each                = local.buckets
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "todos" {
  for_each = local.buckets
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.datos.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "todos" {
  for_each = local.buckets
  bucket   = each.value
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "datos" {
  for_each = {
    kyc            = aws_s3_bucket.kyc.id
    estados_cuenta = aws_s3_bucket.estados_cuenta.id
    cloudtrail     = aws_s3_bucket.cloudtrail.id
  }
  bucket        = each.value
  target_bucket = aws_s3_bucket.logs_acceso.id
  target_prefix = "${each.key}/"
}

resource "aws_s3_bucket_lifecycle_configuration" "todos" {
  for_each = local.buckets
  bucket   = each.value
  rule {
    id     = "retencion"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# Solo HTTPS (TLS) y solo el rol del microservicio KYC puede leer
resource "aws_s3_bucket_policy" "kyc" {
  bucket = aws_s3_bucket.kyc.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenegarSinTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.kyc.arn, "${aws_s3_bucket.kyc.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "LecturaSoloServicioKYC"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.svc_kyc.arn }
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = "${aws_s3_bucket.kyc.arn}/*"
      }
    ]
  })
}

# ---------------------------------------------------------------------
# Aurora PostgreSQL (CB-06, CB-09)
# ---------------------------------------------------------------------
resource "aws_db_subnet_group" "db" {
  name       = "neoquetzal-db"
  subnet_ids = [aws_subnet.privada_a.id, aws_subnet.privada_b.id]
}

resource "aws_rds_cluster_parameter_group" "pg" {
  name   = "neoquetzal-aurora-pg15"
  family = "aurora-postgresql15"

  parameter {
    name  = "log_statement"
    value = "ddl"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_rds_cluster" "core" {
  cluster_identifier                  = "neoquetzal-core"
  engine                              = "aurora-postgresql"
  engine_version                      = "15.4"
  database_name                       = "neoquetzal"
  master_username                     = "neoquetzal_master"
  manage_master_user_password         = true # la contrasena la genera y rota Secrets Manager
  master_user_secret_kms_key_id       = aws_kms_key.datos.arn
  iam_database_authentication_enabled = true # la app usa un rol IAM de menor privilegio, no el master
  db_subnet_group_name                = aws_db_subnet_group.db.name
  db_cluster_parameter_group_name     = aws_rds_cluster_parameter_group.pg.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.datos.arn
  backup_retention_period             = 35
  copy_tags_to_snapshot               = true
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "neoquetzal-core-final"
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}

resource "aws_iam_role" "rds_monitoring" {
  name = "neoquetzal-rds-monitoring"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_rds_cluster_instance" "core_1" {
  identifier                            = "neoquetzal-core-1"
  cluster_identifier                    = aws_rds_cluster.core.id
  instance_class                        = "db.r6g.large"
  engine                                = aws_rds_cluster.core.engine
  publicly_accessible                   = false
  auto_minor_version_upgrade            = true
  monitoring_interval                   = 30
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.datos.arn
}

# Respaldo gestionado (AWS Backup)
resource "aws_backup_vault" "principal" {
  name        = "neoquetzal-backup"
  kms_key_arn = aws_kms_key.datos.arn
}

resource "aws_backup_plan" "diario" {
  name = "neoquetzal-diario"
  rule {
    rule_name         = "diario-35-dias"
    target_vault_name = aws_backup_vault.principal.name
    schedule          = "cron(0 5 * * ? *)"
    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_iam_role" "backup" {
  name = "neoquetzal-backup"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "aurora" {
  name         = "aurora-core"
  plan_id      = aws_backup_plan.diario.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = [aws_rds_cluster.core.arn]
}

# ---------------------------------------------------------------------
# Secretos (CB-09): cifrados con KMS propio y con rotacion
# ---------------------------------------------------------------------
resource "aws_secretsmanager_secret" "api_core" {
  name       = "neoquetzal/api-core-bancario"
  kms_key_id = aws_kms_key.datos.arn
}

resource "aws_secretsmanager_secret_rotation" "api_core" {
  secret_id           = aws_secretsmanager_secret.api_core.id
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:${local.cuenta}:function:neoquetzal-rotar-secreto"
  rotation_rules {
    automatically_after_days = 30
  }
}

# ---------------------------------------------------------------------
# IAM de menor privilegio (CB-09, CB-10)
# - Sin usuarios IAM ni llaves de larga duracion: GitHub Actions usa OIDC.
# - Cada rol solo tiene las acciones y recursos que necesita.
# ---------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "cicd" {
  name                 = "neoquetzal-cicd"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:neoquetzal/neoquetzal-lab:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "cicd" {
  name = "publicar-imagen-y-desplegar"
  role = aws_iam_role.cicd.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "LoginECR"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*" # esta accion no admite restringir por recurso
      },
      {
        Sid    = "PublicarImagen"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage"
        ]
        Resource = aws_ecr_repository.api.arn
      },
      {
        Sid      = "DescribirCluster"
        Effect   = "Allow"
        Action   = ["eks:DescribeCluster"]
        Resource = aws_eks_cluster.neoquetzal.arn
      }
    ]
  })
}

# Rol del microservicio KYC (IRSA): solo su bucket y su llave
resource "aws_iam_role" "svc_kyc" {
  name = "neoquetzal-svc-kyc"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::${local.cuenta}:oidc-provider/oidc.eks.us-east-1.amazonaws.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
    }]
  })
}

resource "aws_iam_role_policy" "svc_kyc" {
  name = "kyc-menor-privilegio"
  role = aws_iam_role.svc_kyc.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.kyc.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.datos.arn
      }
    ]
  })
}

# ---------------------------------------------------------------------
# Contenedores: ECR y EKS
# ---------------------------------------------------------------------
resource "aws_ecr_repository" "api" {
  name                 = "neoquetzal-api"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.datos.arn
  }
}

resource "aws_iam_role" "eks" {
  name = "neoquetzal-eks"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks" {
  role       = aws_iam_role.eks.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "neoquetzal" {
  name                      = "neoquetzal-eks"
  role_arn                  = aws_iam_role.eks.arn
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids              = [aws_subnet.privada_a.id, aws_subnet.privada_b.id]
    security_group_ids      = [aws_security_group.eks_nodos.id]
    endpoint_public_access  = false
    endpoint_private_access = true
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.datos.arn
    }
  }
}

# ---------------------------------------------------------------------
# Auditoria (CB-07): CloudTrail multi-region, validado, cifrado, a CloudWatch
# ---------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/neoquetzal/cloudtrail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.datos.arn
}

resource "aws_iam_role" "cloudtrail" {
  name = "neoquetzal-cloudtrail"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail" {
  name = "escribir-cloudwatch"
  role = aws_iam_role.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_sns_topic" "alertas_seguridad" {
  name              = "neoquetzal-alertas-seguridad"
  kms_master_key_id = aws_kms_key.datos.arn
}

resource "aws_cloudtrail" "principal" {
  name                          = "neoquetzal-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.datos.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail.arn
  sns_topic_name                = aws_sns_topic.alertas_seguridad.name

  # Registrar accesos a los documentos KYC (eventos de datos)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.kyc.arn}/"]
    }
  }
}

# ---------------------------------------------------------------------
# API Gateway: logs de acceso, trazas X-Ray y WAF asociado
# ---------------------------------------------------------------------
resource "aws_api_gateway_rest_api" "neoquetzal" {
  name = "neoquetzal-api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_deployment" "v1" {
  rest_api_id = aws_api_gateway_rest_api.neoquetzal.id
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name              = "/neoquetzal/api-gateway"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.datos.arn
}

resource "aws_api_gateway_stage" "prod" {
  # checkov:skip=CKV_AWS_120:No se usa cache: las respuestas contienen saldos y datos personales que no deben quedar en cache.
  # checkov:skip=CKV2_AWS_51:La autenticacion de clientes es OAuth2 + PKCE con Cognito; mTLS se aplica entre API Gateway y EKS (VPC Link), no con la app movil.
  rest_api_id          = aws_api_gateway_rest_api.neoquetzal.id
  deployment_id        = aws_api_gateway_deployment.v1.id
  stage_name           = "prod"
  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn
    format = jsonencode({
      requestId = "$context.requestId", ip = "$context.identity.sourceIp",
      user = "$context.authorizer.claims.sub", ruta = "$context.resourcePath",
      metodo = "$context.httpMethod", estado = "$context.status"
    })
  }
}

resource "aws_api_gateway_method_settings" "todos" {
  # checkov:skip=CKV_AWS_225:Cache deshabilitada a proposito: respuestas con saldos y datos personales (mismo criterio que CKV_AWS_120).
  rest_api_id = aws_api_gateway_rest_api.neoquetzal.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"
  settings {
    logging_level          = "INFO"
    metrics_enabled        = true
    throttling_rate_limit  = 50  # anti fuerza bruta / abuso (R-02)
    throttling_burst_limit = 100
  }
}

# WAF regional con reglas administradas OWASP y limite de tasa (detalle en Fase 6)
resource "aws_wafv2_web_acl" "api" {
  name  = "neoquetzal-api-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "badinputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "LimiteLogin"
    priority = 4
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string         = "/auth/login"
            positional_constraint = "STARTS_WITH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "limitelogin"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesAnonymousIpList"
    priority = 5
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAnonymousIpList"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "anonymousip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "neoquetzal-api-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudwatch_log_group" "waf" {
  # El nombre debe empezar con aws-waf-logs-
  name              = "aws-waf-logs-neoquetzal"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.datos.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "api" {
  resource_arn            = aws_wafv2_web_acl.api.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}

resource "aws_wafv2_web_acl_association" "api" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.api.arn
}
