# ==============================================================================
# Verix Zero-Trust IaC — Phase 4: KMS Envelope Secrets & mTLS PKI Identity
# ==============================================================================
# Provisions Customer-Managed Encryption Keys (AWS KMS CMK & GCP Cloud KMS CMEK),
# hardware-backed Secret Manager stores for PQC root key material
# (VERIX_NODE_KEY_MATERIAL / ML-DSA-65 seed), and SPIFFE-compliant X.509 mTLS
# certificates for cross-cloud node-to-node quorum gossip.
# ==============================================================================

terraform {
  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# ------------------------------------------------------------------------------
# 1. AWS KMS Customer Managed Key (CMK) & Secrets Manager (Envelope Encryption)
# ------------------------------------------------------------------------------
data "aws_iam_policy_document" "verix_kms_cmk_policy" {
  statement {
    sid       = "EnableAccountRootAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowFargateRuntimeDecryptOnly"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.verix_ecs_execution_role.arn,
        aws_iam_role.verix_ecs_task_role.arn
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "verix_pqc_cmk" {
  description             = "Verix Zero-Trust CMK protecting PQC ML-DSA/ML-KEM seed material and mTLS keys"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90
  policy                  = data.aws_iam_policy_document.verix_kms_cmk_policy.json
}

resource "aws_kms_alias" "verix_pqc_cmk_alias" {
  name          = "alias/verix-pqc-zero-trust-cmk"
  target_key_id = aws_kms_key.verix_pqc_cmk.key_id
}

resource "aws_secretsmanager_secret" "verix_aws_pqc_seed" {
  name                    = "verix/prod/aws-node/pqc-key-material"
  description             = "FIPS 204 ML-DSA-65 & FIPS 203 ML-KEM-768 root derivation seed for verix-node-aws-1"
  kms_key_id              = aws_kms_key.verix_pqc_cmk.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "verix_aws_mtls_bundle" {
  name                    = "verix/prod/aws-node/mtls-spiffe-bundle"
  description             = "TLS 1.3 mTLS X.509 client/server certificate, ECDSA P-384 key, and Root CA bundle"
  kms_key_id              = aws_kms_key.verix_pqc_cmk.arn
  recovery_window_in_days = 30
}

# Least-Privilege Secret Retrieval Policy (Scoped strictly to the two Verix Secret ARNs)
data "aws_iam_policy_document" "verix_aws_secrets_read" {
  statement {
    sid    = "VerixRuntimeReadPQCAndMTLSSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = [
      aws_secretsmanager_secret.verix_aws_pqc_seed.arn,
      aws_secretsmanager_secret.verix_aws_mtls_bundle.arn
    ]
  }

  statement {
    sid    = "VerixRuntimeDecryptSecretsViaKMS"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = [
      aws_kms_key.verix_pqc_cmk.arn
    ]
  }
}

resource "aws_iam_policy" "verix_aws_secrets_policy" {
  name        = "verix-aws-node-secrets-least-privilege"
  description = "Grants Fargate runtime read-only access to KMS-encrypted PQC seed and mTLS bundle"
  policy      = data.aws_iam_policy_document.verix_aws_secrets_read.json
}

resource "aws_iam_role_policy_attachment" "verix_ecs_exec_secrets_binding" {
  role       = aws_iam_role.verix_ecs_execution_role.name
  policy_arn = aws_iam_policy.verix_aws_secrets_policy.arn
}

resource "aws_iam_role_policy_attachment" "verix_ecs_task_secrets_binding" {
  role       = aws_iam_role.verix_ecs_task_role.name
  policy_arn = aws_iam_policy.verix_aws_secrets_policy.arn
}

# ------------------------------------------------------------------------------
# 2. GCP Cloud KMS (CMEK) & Secret Manager (Hardware-Backed Secret Isolation)
# ------------------------------------------------------------------------------
resource "google_kms_key_ring" "verix_keyring" {
  project  = var.gcp_project_id
  name     = "verix-zero-trust-keyring"
  location = var.gcp_region
}

resource "google_kms_crypto_key" "verix_pqc_cmek" {
  name                       = "verix-pqc-secret-cmek"
  key_ring                   = google_kms_key_ring.verix_keyring.id
  rotation_period            = "7776000s" # 90-day automated rotation
  destroy_scheduled_duration = "2592000s" # 30-day destruction hold

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_secret_manager_secret" "verix_gcp_pqc_seed" {
  project   = var.gcp_project_id
  secret_id = "verix-gcp-node-pqc-key-material"

  replication {
    user_managed {
      replicas {
        location = var.gcp_region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.verix_pqc_cmek.id
        }
      }
    }
  }
}

resource "google_secret_manager_secret" "verix_gcp_mtls_bundle" {
  project   = var.gcp_project_id
  secret_id = "verix-gcp-node-mtls-spiffe-bundle"

  replication {
    user_managed {
      replicas {
        location = var.gcp_region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.verix_pqc_cmek.id
        }
      }
    }
  }
}

# Resource-Level Secret Accessor Binding (No project-wide secret access!)
resource "google_secret_manager_secret_iam_member" "verix_gcp_pqc_seed_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.verix_gcp_pqc_seed.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.verix_gcp_node_runtime.email}"
}

resource "google_secret_manager_secret_iam_member" "verix_gcp_mtls_bundle_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.verix_gcp_mtls_bundle.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.verix_gcp_node_runtime.email}"
}

# ------------------------------------------------------------------------------
# 3. Zero-Trust Internal PKI & SPIFFE X.509 mTLS Certificates (ECDSA P-384)
# ------------------------------------------------------------------------------
resource "tls_private_key" "verix_root_ca_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "tls_self_signed_cert" "verix_root_ca_cert" {
  private_key_pem = tls_private_key.verix_root_ca_key.private_key_pem

  subject {
    common_name  = "Verix Zero-Trust Multi-Cloud Root CA"
    organization = "Verix PQC Trust Infrastructure"
  }

  validity_period_hours = 8760 # 1 year Root CA
  early_renewal_hours   = 720
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature"
  ]
}

# AWS Node mTLS Identity (SPIFFE ID: spiffe://verix.internal/ns/prod/node/verix-node-aws-1)
resource "tls_private_key" "verix_aws_node_mtls_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "tls_cert_request" "verix_aws_node_csr" {
  private_key_pem = tls_private_key.verix_aws_node_mtls_key.private_key_pem

  subject {
    common_name  = "verix-node-aws-1.verix.internal"
    organization = "Verix AWS Quorum Node"
  }

  dns_names = ["verix-node-aws-1.verix.internal"]
  uris      = ["spiffe://verix.internal/ns/prod/node/verix-node-aws-1"]
}

resource "tls_locally_signed_cert" "verix_aws_node_mtls_cert" {
  cert_request_pem   = tls_cert_request.verix_aws_node_csr.cert_request_pem
  ca_private_key_pem = tls_private_key.verix_root_ca_key.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.verix_root_ca_cert.cert_pem

  validity_period_hours = 720 # Short-lived 30-day leaf certificate
  early_renewal_hours   = 168

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
    "client_auth"
  ]
}

# GCP Node mTLS Identity (SPIFFE ID: spiffe://verix.internal/ns/prod/node/verix-node-gcp-1)
resource "tls_private_key" "verix_gcp_node_mtls_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "tls_cert_request" "verix_gcp_node_csr" {
  private_key_pem = tls_private_key.verix_gcp_node_mtls_key.private_key_pem

  subject {
    common_name  = "verix-node-gcp-1.verix.internal"
    organization = "Verix GCP Quorum Node"
  }

  dns_names = ["verix-node-gcp-1.verix.internal"]
  uris      = ["spiffe://verix.internal/ns/prod/node/verix-node-gcp-1"]
}

resource "tls_locally_signed_cert" "verix_gcp_node_mtls_cert" {
  cert_request_pem   = tls_cert_request.verix_gcp_node_csr.cert_request_pem
  ca_private_key_pem = tls_private_key.verix_root_ca_key.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.verix_root_ca_cert.cert_pem

  validity_period_hours = 720 # Short-lived 30-day leaf certificate
  early_renewal_hours   = 168

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
    "client_auth"
  ]
}
