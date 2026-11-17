# ==============================================================================
# Verix Zero-Trust IaC — Provider Constraints & Multi-Cloud Configuration
# ==============================================================================

terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 6.12"
    }
  }
}

variable "aws_region" {
  description = "Primary AWS region for the Verix ledger node and state backend"
  type        = string
  default     = "us-east-1"
}

variable "gcp_project_id" {
  description = "Target Google Cloud Project ID hosting the GCP Verix ledger node"
  type        = string
}

variable "gcp_region" {
  description = "Primary GCP region for regional identity and compute resources"
  type        = string
  default     = "us-central1"
}

variable "github_repository" {
  description = "GitHub owner/repository authorized for OIDC federation"
  type        = string
  default     = "Keninjavelas/Verix"
}

variable "tf_state_bucket" {
  description = "Bootstrapped S3 bucket storing the encrypted Terraform state"
  type        = string
  default     = "verix-tfstate-production"
}

variable "tf_lock_table" {
  description = "Bootstrapped DynamoDB table enforcing Terraform state locking"
  type        = string
  default     = "verix-terraform-lock"
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project      = "Verix"
      Component    = "ZeroTrust-PQC-Audit-Ledger"
      ManagedBy    = "Terraform"
      SecurityTier = "Critical-Immutable"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}
