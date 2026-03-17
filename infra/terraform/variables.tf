# MPC Wallet — Terraform Variables

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "mpc-wallet"
}

variable "environment" {
  description = "Deployment environment: dev, staging, production"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, production."
  }
}

variable "mpc_node_count" {
  description = "Number of MPC nodes (should match threshold config total_parties)"
  type        = number
  default     = 3
}

# ── AWS ─────────────────────────────────────────────────────────────

variable "enable_aws" {
  description = "Deploy to AWS"
  type        = bool
  default     = true
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aws_instance_type" {
  description = "EC2 instance type for EKS nodes"
  type        = string
  default     = "m6i.large"
}

# ── GCP ─────────────────────────────────────────────────────────────

variable "enable_gcp" {
  description = "Deploy to GCP"
  type        = bool
  default     = false
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "gcp_machine_type" {
  description = "GCE machine type for GKE nodes"
  type        = string
  default     = "e2-standard-4"
}

# ── Azure ───────────────────────────────────────────────────────────

variable "enable_azure" {
  description = "Deploy to Azure"
  type        = bool
  default     = false
}

variable "azure_location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "azure_vm_size" {
  description = "VM size for AKS nodes"
  type        = string
  default     = "Standard_D4s_v3"
}
