# ==============================================================================
# Verix Zero-Trust IaC — GCP Workload Identity Federation (WIF)
# ==============================================================================
# Eliminates long-lived JSON Service Account keys by exchanging GitHub OIDC
# tokens for short-lived Google Cloud STS credentials via Workload Identity Pool.
# ==============================================================================

# 1. Dedicated Workload Identity Pool for GitHub Actions
resource "google_iam_workload_identity_pool" "verix_github_pool" {
  project                   = var.gcp_project_id
  workload_identity_pool_id = "verix-github-pool"
  display_name              = "Verix GitHub Actions Pool"
  description               = "Zero-Trust identity pool for Verix CI/CD pipelines"
  disabled                  = false
}

# 2. OIDC Provider Mapping & CEL Attribute Condition Gate
resource "google_iam_workload_identity_pool_provider" "verix_github_provider" {
  project                            = var.gcp_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.verix_github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "verix-github-provider"
  display_name                       = "Verix GitHub OIDC Provider"
  description                        = "OIDC provider validating GitHub Actions JWT assertions"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  # CEL expression evaluated at the Google STS boundary: rejects tokens from any
  # other GitHub repository or non-main branch before IAM evaluation even occurs.
  attribute_condition = "assertion.repository == '${var.github_repository}' && assertion.ref == 'refs/heads/main'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# 3. Dedicated GCP Service Account for Terraform Execution
resource "google_service_account" "verix_terraform_sa" {
  project      = var.gcp_project_id
  account_id   = "verix-terraform-deployer"
  display_name = "Verix Terraform Deployer Service Account"
  description  = "Impersonated via Workload Identity Federation by GitHub Actions"
}

# 4. Bind Workload Identity Pool Principal to Service Account (Gated to Repository)
resource "google_service_account_iam_member" "verix_wif_impersonation" {
  service_account_id = google_service_account.verix_terraform_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.verix_github_pool.name}/attribute.repository/${var.github_repository}"
}

# 5. Least-Privilege Custom Role for Firestore Database Provisioning
resource "google_project_iam_custom_role" "verix_firestore_provisioner" {
  project     = var.gcp_project_id
  role_id     = "verixFirestoreProvisioner"
  title       = "Verix Firestore Ledger Provisioner"
  description = "Strictly scoped permissions to manage only Firestore database and index definitions"
  permissions = [
    "datastore.databases.create",
    "datastore.databases.get",
    "datastore.databases.getMetadata",
    "datastore.databases.list",
    "datastore.databases.update",
    "datastore.indexes.create",
    "datastore.indexes.delete",
    "datastore.indexes.get",
    "datastore.indexes.list",
    "datastore.indexes.update",
    "datastore.operations.get",
    "datastore.operations.list"
  ]
}

resource "google_project_iam_member" "verix_terraform_firestore_binding" {
  project = var.gcp_project_id
  role    = google_project_iam_custom_role.verix_firestore_provisioner.id
  member  = "serviceAccount:${google_service_account.verix_terraform_sa.email}"
}

output "gcp_workload_identity_provider" {
  description = "Full resource name of the GCP Workload Identity Provider for GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.verix_github_provider.name
}

output "gcp_terraform_service_account_email" {
  description = "Email of the GCP Service Account impersonated by GitHub Actions"
  value       = google_service_account.verix_terraform_sa.email
}
