# ==============================================================================
# Verix Zero-Trust IaC — Encrypted S3 Remote State & DynamoDB State Locking
# ==============================================================================
# Consumes the out-of-band state infrastructure provisioned by bootstrap-state.sh.
# Encryption in transit (TLS) and at rest (SSE-S3) are enforced alongside
# distributed mutex locking via DynamoDB LockID conditional writes.
# ==============================================================================

terraform {
  backend "s3" {
    bucket         = "verix-tfstate-production"
    key            = "global/verix-ledger/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "verix-terraform-lock"
    encrypt        = true
  }
}
