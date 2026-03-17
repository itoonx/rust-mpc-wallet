# MPC Wallet — Terraform Outputs

output "aws_cluster_endpoint" {
  description = "AWS EKS cluster endpoint"
  value       = var.enable_aws ? module.aws[0].cluster_endpoint : null
}

output "aws_kms_key_arn" {
  description = "AWS KMS key ARN for key share encryption"
  value       = var.enable_aws ? module.aws[0].kms_key_arn : null
}

output "gcp_cluster_endpoint" {
  description = "GCP GKE cluster endpoint"
  value       = var.enable_gcp ? module.gcp[0].cluster_endpoint : null
}

output "gcp_kms_key_name" {
  description = "GCP Cloud KMS key resource name"
  value       = var.enable_gcp ? module.gcp[0].kms_key_name : null
}

output "azure_cluster_fqdn" {
  description = "Azure AKS cluster FQDN"
  value       = var.enable_azure ? module.azure[0].cluster_fqdn : null
}

output "azure_key_vault_uri" {
  description = "Azure Key Vault URI for key share encryption"
  value       = var.enable_azure ? module.azure[0].key_vault_uri : null
}
