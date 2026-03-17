# MPC Wallet — Deployment Guide

Step-by-step deployment guide for Docker, Kubernetes, and Terraform.

---

## Prerequisites

- Rust 1.82+ (for building from source)
- Docker 24+ and Docker Compose v2
- kubectl 1.28+ (for Kubernetes)
- Terraform 1.5+ (for cloud deployment)
- NATS Server 2.10+ (for MPC inter-party transport)

---

## Option 1: Local Development (Docker Compose)

The fastest way to run a local 3-node MPC cluster.

```bash
# 1. Clone and build
git clone https://github.com/example/mpc-wallet.git
cd mpc-wallet

# 2. Set environment variables
export JWT_SECRET="your-secret-at-least-32-bytes-long"
export API_KEYS="dev-api-key-1,dev-api-key-2"

# 3. Start the cluster
docker compose -f infra/docker/docker-compose.yml up -d

# 4. Verify
curl http://localhost:3000/v1/health
# {"success":true,"data":{"status":"healthy","version":"0.1.0","chains_supported":50}}

curl http://localhost:3000/v1/chains | jq '.data.total'
# 50
```

### Architecture (local)
```
┌──────────────┐
│  API Gateway │ :3000
└──────┬───────┘
       │
┌──────┼──────────────────────┐
│      │        NATS :4222    │
│  ┌───┴───┐  ┌───────┐  ┌───────┐
│  │Node 1 │  │Node 2 │  │Node 3 │
│  │ :3001 │  │ :3002 │  │ :3003 │
│  └───────┘  └───────┘  └───────┘
└─────────────────────────────────┘
```

---

## Option 2: Kubernetes

### 1. Create namespace and secrets

```bash
kubectl create namespace mpc-wallet

# Create secrets (use sealed-secrets or external-secrets in production)
kubectl create secret generic mpc-secrets \
  --namespace mpc-wallet \
  --from-literal=jwt_secret="$JWT_SECRET" \
  --from-literal=api_keys="$API_KEYS" \
  --from-literal=encryption_password="$ENCRYPTION_PASSWORD"
```

### 2. Apply manifests

```bash
kubectl apply -f infra/k8s/configmap.yaml
kubectl apply -f infra/k8s/deployment.yaml
kubectl apply -f infra/k8s/service.yaml
kubectl apply -f infra/k8s/ingress.yaml
```

### 3. Verify

```bash
# Wait for pods
kubectl get pods -n mpc-wallet -w

# Check health
kubectl port-forward svc/mpc-api-gateway 3000:80 -n mpc-wallet &
curl http://localhost:3000/v1/health
```

### 4. Deploy NATS (if not using managed NATS)

```bash
# Using NATS Helm chart
helm repo add nats https://nats-io.github.io/k8s/helm/charts/
helm install nats nats/nats \
  --namespace mpc-wallet \
  --set jetstream.enabled=true \
  --set jetstream.memStorage.size=256Mi \
  --set jetstream.fileStorage.size=1Gi
```

---

## Option 3: Terraform (Multi-Cloud)

### 1. Configure provider

```bash
cd infra/terraform

# Copy and customize variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your cloud settings
```

### 2. Deploy

```bash
# AWS only (default)
terraform init
terraform plan -var="enable_aws=true"
terraform apply

# Multi-cloud (AWS + GCP)
terraform apply \
  -var="enable_aws=true" \
  -var="enable_gcp=true" \
  -var="gcp_project_id=my-project"

# All three clouds
terraform apply \
  -var="enable_aws=true" \
  -var="enable_gcp=true" \
  -var="enable_azure=true"
```

### 3. Apply K8s manifests to provisioned cluster

```bash
# AWS
aws eks update-kubeconfig --name mpc-wallet-production
kubectl apply -f infra/k8s/

# GCP
gcloud container clusters get-credentials mpc-wallet-production
kubectl apply -f infra/k8s/
```

---

## Configuration Reference

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `PORT` | HTTP listen port | `3000` |
| `NETWORK` | Chain network: mainnet, testnet, devnet | `testnet` |
| `JWT_SECRET` | HMAC secret for JWT validation | (required in prod) |
| `API_KEYS` | Comma-separated API keys | (empty) |
| `NATS_URL` | NATS server URL | `nats://localhost:4222` |
| `PARTY_ID` | MPC party identifier | (auto from hostname) |
| `RATE_LIMIT_RPS` | Max requests/second per IP | `100` |
| `RUST_LOG` | Log level filter | `info` |

---

## Security Checklist

Before going to production:

- [ ] Change `JWT_SECRET` from default to a strong random value (32+ bytes)
- [ ] Set `API_KEYS` to known, rotatable service keys
- [ ] Enable TLS via ingress (cert-manager + Let's Encrypt)
- [ ] Use sealed-secrets or external secrets operator for K8s secrets
- [ ] Enable KMS envelope encryption for key shares (AWS KMS / GCP Cloud KMS / Azure Key Vault)
- [ ] Configure NATS mTLS (`NatsTlsConfig` in transport layer)
- [ ] Set `NETWORK=mainnet` only after thorough testnet validation
- [ ] Enable Prometheus monitoring and set up alerts (see MONITORING.md)
- [ ] Review RBAC roles — minimize Admin access
- [ ] Ensure audit ledger is backed up to WORM storage
