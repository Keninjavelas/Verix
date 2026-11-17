# ==============================================================================
# Verix Zero-Trust IaC — Phase 3 Deliverable 2: GCP Cloud Run Service
# ==============================================================================
# Provisions `verix-node-gcp` on Cloud Run v2 consuming the GHCR digest-pinned
# container image, running under `verix-gcp-node-runtime` from Phase 2, locking
# ingress to `INGRESS_TRAFFIC_INTERNAL_ONLY`, and routing outbound traffic
# through Direct VPC Egress (`ALL_TRAFFIC`).
# ==============================================================================

variable "gcp_vpc_network" {
  description = "Name or self_link of the GCP VPC network for Direct VPC Egress"
  type        = string
  default     = "verix-zero-trust-vpc"
}

variable "gcp_vpc_subnetwork" {
  description = "Name or self_link of the private GCP VPC subnetwork for Direct VPC Egress"
  type        = string
  default     = "verix-private-subnet-us-central1"
}

resource "google_cloud_run_v2_service" "verix_node_gcp" {
  project             = var.gcp_project_id
  name                = "verix-node-gcp"
  location            = var.gcp_region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = true

  template {
    # Runs strictly under the append-only Service Account provisioned in Phase 2
    service_account       = google_service_account.verix_gcp_node_runtime.email
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }

    # Direct VPC Egress: forces all outbound traffic through the private VPC
    # network so Private Google Access handles Firestore traffic off the public internet
    vpc_access {
      egress = "ALL_TRAFFIC"
      network_interfaces {
        network    = var.gcp_vpc_network
        subnetwork = var.gcp_vpc_subnetwork
        tags       = ["verix-node-gcp", "zero-trust-compute"]
      }
    }

    # Ephemeral RAM-backed tmpfs volume for /var/lib/verix
    volumes {
      name = "verix-ephemeral-ram"
      empty_dir {
        medium     = "MEMORY"
        size_limit = "256Mi"
      }
    }

    containers {
      name  = "verix-api"
      image = var.container_image_digest

      ports {
        container_port = 4317
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "1024Mi"
        }
        cpu_idle = false
      }

      env {
        name  = "NODE_ENV"
        value = "production"
      }
      env {
        name  = "VERIX_HOST"
        value = "0.0.0.0"
      }
      env {
        name  = "VERIX_PORT"
        value = "4317"
      }
      env {
        name  = "VERIX_BACKEND"
        value = "firestore"
      }
      env {
        name  = "VERIX_DATA_DIR"
        value = "/var/lib/verix"
      }

      volume_mounts {
        name       = "verix-ephemeral-ram"
        mount_path = "/var/lib/verix"
      }

      startup_probe {
        http_get {
          path = "/health"
          port = 4317
        }
        initial_delay_seconds = 3
        period_seconds        = 5
        failure_threshold     = 6
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 4317
        }
        period_seconds    = 15
        failure_threshold = 3
      }
    }
  }
}

output "gcp_cloud_run_service_uri" {
  description = "Internal-only URI of the GCP Cloud Run Verix service"
  value       = google_cloud_run_v2_service.verix_node_gcp.uri
}
