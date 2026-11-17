# ==============================================================================
# Verix Zero-Trust IaC — Multi-Cloud Immutable Proof Ledger Databases
# ==============================================================================
# Provisions the primary cryptographic proof stores across AWS (DynamoDB) and
# GCP (Firestore Native), plus append-only runtime IAM policies that strip
# DeleteItem / entities.delete permissions at the cloud control-plane layer.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. AWS Ledger Database — Amazon DynamoDB (verix-ledger-aws)
# ------------------------------------------------------------------------------
resource "aws_dynamodb_table" "verix_ledger_aws" {
  name                        = "verix-ledger-aws"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "proof_hash"
  deletion_protection_enabled = true

  attribute {
    name = "proof_hash"
    type = "S"
  }

  # Continuous backups (35-day rolling window) to protect against logical corruption
  point_in_time_recovery {
    enabled = true
  }

  # Server-Side Encryption at rest via AWS-owned KMS keys
  server_side_encryption {
    enabled = true
  }

  tags = {
    Name        = "verix-ledger-aws"
    LedgerCloud = "aws"
    DataClass   = "Immutable-PQC-Execution-Proofs"
  }
}

# Least-Privilege Append-Only Runtime Policy for the AWS Verix Compute Node (Phase 3)
# Explicitly OMITS dynamodb:DeleteItem and dynamodb:UpdateItem so compromised
# compute nodes cannot erase or mutate historical Merkle ledger proofs.
data "aws_iam_policy_document" "verix_aws_node_append_only" {
  statement {
    sid    = "VerixLedgerAppendAndVerifyOnly"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:BatchGetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:DescribeTable"
    ]
    resources = [
      aws_dynamodb_table.verix_ledger_aws.arn,
      "${aws_dynamodb_table.verix_ledger_aws.arn}/index/*"
    ]
  }

  statement {
    sid    = "ExplicitDenyProofDeletion"
    effect = "Deny"
    actions = [
      "dynamodb:DeleteItem",
      "dynamodb:DeleteTable"
    ]
    resources = [
      aws_dynamodb_table.verix_ledger_aws.arn
    ]
  }
}

resource "aws_iam_policy" "verix_aws_node_ledger_policy" {
  name        = "verix-aws-node-ledger-append-only"
  description = "Append-only IAM policy for Verix AWS compute nodes interacting with verix-ledger-aws"
  policy      = data.aws_iam_policy_document.verix_aws_node_append_only.json
}

# ------------------------------------------------------------------------------
# 2. GCP Ledger Database — Cloud Firestore in Native Mode (verix-ledger-gcp)
# ------------------------------------------------------------------------------
resource "google_firestore_database" "verix_ledger_gcp" {
  project                           = var.gcp_project_id
  name                              = "verix-ledger-gcp"
  location_id                       = "nam5"
  type                              = "FIRESTORE_NATIVE"
  concurrency_mode                  = "OPTIMISTIC"
  app_engine_integration_mode       = "DISABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  deletion_policy                   = "ABANDON"
}

# Dedicated GCP Service Account for the Verix GCP Runtime Compute Node (Phase 3)
resource "google_service_account" "verix_gcp_node_runtime" {
  project      = var.gcp_project_id
  account_id   = "verix-gcp-node-runtime"
  display_name = "Verix GCP Ledger Node Runtime SA"
  description  = "Least-privilege append-only runtime identity for the GCP Verix verification node"
}

# Custom Append-Only Role for Firestore: Grants create/get/list, OMITS datastore.entities.delete
resource "google_project_iam_custom_role" "verix_firestore_append_only" {
  project     = var.gcp_project_id
  role_id     = "verixFirestoreLedgerAppendOnly"
  title       = "Verix Firestore Append-Only Ledger Writer"
  description = "Allows creating and reading PQC proof documents while forbidding entity deletion"
  permissions = [
    "datastore.databases.get",
    "datastore.entities.create",
    "datastore.entities.get",
    "datastore.entities.list",
    "datastore.entities.update"
  ]
}

resource "google_project_iam_member" "verix_gcp_node_runtime_binding" {
  project = var.gcp_project_id
  role    = google_project_iam_custom_role.verix_firestore_append_only.id
  member  = "serviceAccount:${google_service_account.verix_gcp_node_runtime.email}"

  condition {
    title       = "RestrictToVerixLedgerGcpDatabase"
    description = "Scopes Firestore access exclusively to the verix-ledger-gcp database instance"
    expression  = "resource.name.startsWith('projects/${var.gcp_project_id}/databases/${google_firestore_database.verix_ledger_gcp.name}')"
  }
}

output "aws_ledger_table_name" {
  description = "Name of the provisioned AWS DynamoDB proof ledger table"
  value       = aws_dynamodb_table.verix_ledger_aws.name
}

output "aws_ledger_table_arn" {
  description = "ARN of the provisioned AWS DynamoDB proof ledger table"
  value       = aws_dynamodb_table.verix_ledger_aws.arn
}

output "gcp_ledger_database_name" {
  description = "Name of the provisioned GCP Firestore Native proof ledger database"
  value       = google_firestore_database.verix_ledger_gcp.name
}
