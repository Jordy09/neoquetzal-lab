# =====================================================================
# NeoQuetzal - Infraestructura AWS (VERSION VULNERABLE)
# Laboratorio academico - Entregable 3, Fase 5 (IaC Hardening)
# Reproduce los problemas base CB-06, CB-07, CB-08, CB-09 y CB-10.
# NO DESPLEGAR. Solo se usa para analisis estatico con Checkov / Trivy.
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

# ---------------------------------------------------------------------
# Red
# ---------------------------------------------------------------------
resource "aws_vpc" "neoquetzal" {
  cidr_block = "10.20.0.0/16"
  tags = { Name = "neoquetzal-vpc" }
}

resource "aws_subnet" "publica_a" {
  vpc_id                  = aws_vpc.neoquetzal.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true # todo queda con IP publica
}

resource "aws_subnet" "publica_b" {
  vpc_id                  = aws_vpc.neoquetzal.id
  cidr_block              = "10.20.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
}

# SG de administracion: SSH abierto a todo internet
resource "aws_security_group" "admin" {
  name        = "neoquetzal-admin"
  description = "Acceso de administracion"
  vpc_id      = aws_vpc.neoquetzal.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SG de la base de datos: PostgreSQL expuesto a internet
resource "aws_security_group" "db" {
  name        = "neoquetzal-db"
  description = "Base de datos"
  vpc_id      = aws_vpc.neoquetzal.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------
# Almacenamiento S3 (documentos KYC y estados de cuenta) - CB-08
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "kyc" {
  bucket = "neoquetzal-kyc-documentos"
}

# Sin bloqueo de acceso publico
resource "aws_s3_bucket_public_access_block" "kyc" {
  bucket                  = aws_s3_bucket.kyc.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Politica que permite lectura a cualquiera
resource "aws_s3_bucket_policy" "kyc_publico" {
  bucket = aws_s3_bucket.kyc.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "LecturaPublica"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:ListBucket"]
      Resource  = [aws_s3_bucket.kyc.arn, "${aws_s3_bucket.kyc.arn}/*"]
    }]
  })
}

resource "aws_s3_bucket" "estados_cuenta" {
  bucket = "neoquetzal-estados-cuenta"
}

# ---------------------------------------------------------------------
# Base de datos Aurora PostgreSQL - CB-06 / CB-09
# ---------------------------------------------------------------------
resource "aws_db_subnet_group" "db" {
  name       = "neoquetzal-db"
  subnet_ids = [aws_subnet.publica_a.id, aws_subnet.publica_b.id]
}

resource "aws_rds_cluster" "core" {
  cluster_identifier      = "neoquetzal-core"
  engine                  = "aurora-postgresql"
  engine_version          = "15.4"
  database_name           = "neoquetzal"
  master_username         = "admin"                 # usuario administrador usado por la app
  master_password         = "NeoQuetzal2026!"       # secreto en texto plano
  db_subnet_group_name    = aws_db_subnet_group.db.name
  vpc_security_group_ids  = [aws_security_group.db.id]
  storage_encrypted       = false                   # sin cifrado en reposo
  backup_retention_period = 1
  skip_final_snapshot     = true
  deletion_protection     = false
}

resource "aws_rds_cluster_instance" "core_1" {
  identifier          = "neoquetzal-core-1"
  cluster_identifier  = aws_rds_cluster.core.id
  instance_class      = "db.r6g.large"
  engine              = aws_rds_cluster.core.engine
  publicly_accessible = true                         # accesible desde internet
}

# ---------------------------------------------------------------------
# Llaves y secretos
# ---------------------------------------------------------------------
resource "aws_kms_key" "datos" {
  description         = "Llave de datos NeoQuetzal"
  enable_key_rotation = false
}

resource "aws_secretsmanager_secret" "api_core" {
  name = "neoquetzal/api-core-bancario" # sin llave propia ni rotacion
}

# ---------------------------------------------------------------------
# IAM - rol del pipeline CI/CD con permisos totales (CB-09 / CB-10)
# ---------------------------------------------------------------------
resource "aws_iam_role" "cicd" {
  name = "neoquetzal-cicd"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "cicd_admin" {
  name = "neoquetzal-cicd-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cicd_admin" {
  role       = aws_iam_role.cicd.name
  policy_arn = aws_iam_policy.cicd_admin.arn
}

# Usuario IAM con llaves de acceso de larga duracion (usadas en el pipeline)
resource "aws_iam_user" "deploy" {
  name = "neoquetzal-deploy"
}

resource "aws_iam_access_key" "deploy" {
  user = aws_iam_user.deploy.name
}

resource "aws_iam_user_policy" "deploy" {
  name = "deploy-todo"
  user = aws_iam_user.deploy.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "eks:*", "ecr:*"]
      Resource = "*"
    }]
  })
}

# ---------------------------------------------------------------------
# Contenedores: ECR y EKS
# ---------------------------------------------------------------------
resource "aws_ecr_repository" "api" {
  name                 = "neoquetzal-api"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = false
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

resource "aws_eks_cluster" "neoquetzal" {
  name     = "neoquetzal-eks"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids              = [aws_subnet.publica_a.id, aws_subnet.publica_b.id]
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }
  # Sin cifrado de secretos de Kubernetes ni logs del plano de control
}

# ---------------------------------------------------------------------
# Auditoria - CB-07 (logs incompletos)
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "logs" {
  bucket = "neoquetzal-cloudtrail-logs"
}

resource "aws_cloudtrail" "principal" {
  name                          = "neoquetzal-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_log_file_validation    = false
}

# ---------------------------------------------------------------------
# API Gateway (stage sin logs ni trazas)
# ---------------------------------------------------------------------
resource "aws_api_gateway_rest_api" "neoquetzal" {
  name = "neoquetzal-api"
}

resource "aws_api_gateway_deployment" "v1" {
  rest_api_id = aws_api_gateway_rest_api.neoquetzal.id
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.neoquetzal.id
  deployment_id = aws_api_gateway_deployment.v1.id
  stage_name    = "prod"
}
