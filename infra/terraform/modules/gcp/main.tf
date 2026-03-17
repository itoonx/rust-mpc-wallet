# GCP Module — GKE + Cloud KMS for MPC Wallet

variable "environment" { type = string }
variable "cluster_name" { type = string }
variable "project_id" { type = string }
variable "node_count" { type = number }
variable "machine_type" { type = string }
variable "region" { type = string }

# ── Cloud KMS ────────────────────────────────────────────────────────
resource "google_kms_key_ring" "mpc" {
  name     = "${var.cluster_name}-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "mpc" {
  name            = "${var.cluster_name}-key"
  key_ring        = google_kms_key_ring.mpc.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

# ── GKE Cluster ──────────────────────────────────────────────────────
resource "google_container_cluster" "mpc" {
  name     = var.cluster_name
  location = var.region

  initial_node_count       = 1
  remove_default_node_pool = true

  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.mpc.id
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = var.environment == "production"
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
}

resource "google_container_node_pool" "mpc_nodes" {
  name       = "${var.cluster_name}-pool"
  location   = var.region
  cluster    = google_container_cluster.mpc.name
  node_count = var.node_count

  node_config {
    machine_type = var.machine_type
    disk_size_gb = 50
    disk_type    = "pd-ssd"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}

# ── Outputs ──────────────────────────────────────────────────────────
output "cluster_endpoint" {
  value = google_container_cluster.mpc.endpoint
}

output "kms_key_name" {
  value = google_kms_crypto_key.mpc.id
}
