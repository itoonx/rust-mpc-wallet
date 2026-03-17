# Azure Module — AKS + Key Vault for MPC Wallet

variable "environment" { type = string }
variable "cluster_name" { type = string }
variable "node_count" { type = number }
variable "vm_size" { type = string }
variable "location" { type = string }

# ── Resource Group ───────────────────────────────────────────────────
resource "azurerm_resource_group" "mpc" {
  name     = "${var.cluster_name}-rg"
  location = var.location
}

# ── Key Vault ────────────────────────────────────────────────────────
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "mpc" {
  name                = replace("${var.cluster_name}-kv", "-", "")
  location            = azurerm_resource_group.mpc.location
  resource_group_name = azurerm_resource_group.mpc.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium" # HSM-backed keys

  purge_protection_enabled   = true
  soft_delete_retention_days = 90
}

resource "azurerm_key_vault_key" "mpc" {
  name         = "${var.cluster_name}-key"
  key_vault_id = azurerm_key_vault.mpc.id
  key_type     = "RSA"
  key_size     = 4096
  key_opts     = ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
}

# ── AKS Cluster ──────────────────────────────────────────────────────
resource "azurerm_kubernetes_cluster" "mpc" {
  name                = var.cluster_name
  location            = azurerm_resource_group.mpc.location
  resource_group_name = azurerm_resource_group.mpc.name
  dns_prefix          = var.cluster_name

  default_node_pool {
    name       = "mpcpool"
    node_count = var.node_count
    vm_size    = var.vm_size
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
  }

  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }
}

# ── Outputs ──────────────────────────────────────────────────────────
output "cluster_fqdn" {
  value = azurerm_kubernetes_cluster.mpc.fqdn
}

output "key_vault_uri" {
  value = azurerm_key_vault.mpc.vault_uri
}
