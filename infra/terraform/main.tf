# MPC Wallet — Multi-cloud Terraform configuration
# Supports AWS (EKS + KMS), GCP (GKE + Cloud KMS), Azure (AKS + Key Vault)

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

# ── Provider Configuration ──────────────────────────────────────────

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "mpc-wallet"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "azurerm" {
  features {}
}

# ── Module Composition ──────────────────────────────────────────────

module "aws" {
  source = "./modules/aws"
  count  = var.enable_aws ? 1 : 0

  environment    = var.environment
  cluster_name   = "${var.project_name}-${var.environment}"
  node_count     = var.mpc_node_count
  instance_type  = var.aws_instance_type
  region         = var.aws_region
}

module "gcp" {
  source = "./modules/gcp"
  count  = var.enable_gcp ? 1 : 0

  environment    = var.environment
  cluster_name   = "${var.project_name}-${var.environment}"
  project_id     = var.gcp_project_id
  node_count     = var.mpc_node_count
  machine_type   = var.gcp_machine_type
  region         = var.gcp_region
}

module "azure" {
  source = "./modules/azure"
  count  = var.enable_azure ? 1 : 0

  environment    = var.environment
  cluster_name   = "${var.project_name}-${var.environment}"
  node_count     = var.mpc_node_count
  vm_size        = var.azure_vm_size
  location       = var.azure_location
}
