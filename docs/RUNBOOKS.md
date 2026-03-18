# MPC Wallet — Operational Runbooks

Production runbooks for MPC Wallet operators. Each runbook follows a standard format:
**When to use → Prerequisites → Steps → Verification → Rollback**.

---

## 1. Wallet Freeze

**When:** Suspected compromise, anomalous signing activity, or compliance hold.

### Prerequisites
- Admin role with MFA verified
- Wallet ID (group_id) to freeze

### Steps

```bash
# Via API
curl -X POST https://api.example.com/v1/wallets/{wallet_id}/freeze \
  -H "Authorization: Bearer $ADMIN_JWT"

# Via CLI
mpc-wallet-cli freeze --group-id $WALLET_ID
```

### Impact
- All signing requests for this wallet return `KeyFrozen` error
- Key shares remain encrypted on disk (not deleted)
- Wallet metadata remains visible in list endpoints
- Existing in-flight signing sessions are aborted

### Verification
```bash
# Attempt to sign — should return 403/KeyFrozen
curl -X POST https://api.example.com/v1/wallets/{wallet_id}/sign \
  -H "Authorization: Bearer $JWT" \
  -d '{"message": "deadbeef"}'
# Expected: {"success": false, "error": {"code": "KEY_FROZEN", "message": "key group frozen: ..."}}
```

### Unfreeze Procedure
```bash
curl -X POST https://api.example.com/v1/wallets/{wallet_id}/unfreeze \
  -H "Authorization: Bearer $ADMIN_JWT"
```
Requires Admin + MFA. Verify signing works after unfreeze.

---

## 2. Break-Glass Emergency Access

**When:** Normal approval workflow cannot be followed (e.g., approvers unavailable, critical fund movement needed).

### Prerequisites
- Physical access to break-glass credentials (stored in secure vault)
- Two authorized operators present (four-eyes principle)
- Incident ticket opened

### Steps

1. **Open incident ticket** documenting the reason for break-glass
2. **Retrieve break-glass API key** from secure vault (hardware token)
3. **Execute required operation** with audit trail:
   ```bash
   curl -X POST https://api.example.com/v1/wallets/{id}/transactions \
     -H "Authorization: Bearer $BREAK_GLASS_JWT" \
     -d '{"chain": "ethereum", "to": "0x...", "value": "...", ...}'
   ```
4. **Immediately rotate** break-glass credentials after use
5. **File post-incident report** within 24 hours

### Audit Trail
All break-glass operations are logged to the audit ledger with elevated priority.
Export evidence pack for compliance review:
```bash
mpc-wallet-cli audit-verify --export-evidence
```

---

## 3. Incident Response — Suspected Key Compromise

**When:** Evidence of unauthorized access to key shares, unusual signing patterns, or node compromise.

### Steps

1. **Freeze all affected wallets immediately**
   ```bash
   for wallet_id in $AFFECTED_WALLETS; do
     curl -X POST https://api.example.com/v1/wallets/$wallet_id/freeze \
       -H "Authorization: Bearer $ADMIN_JWT"
   done
   ```

2. **Isolate compromised node(s)**
   ```bash
   kubectl cordon mpc-node-$N
   kubectl drain mpc-node-$N --ignore-daemonsets --delete-emptydir-data
   ```

3. **Export audit logs for forensics**
   ```bash
   mpc-wallet-cli audit-verify --export-evidence --since "2024-01-01T00:00:00Z"
   ```

4. **Initiate key refresh** (if shares may be partially compromised)
   ```bash
   curl -X POST https://api.example.com/v1/wallets/{id}/refresh \
     -H "Authorization: Bearer $ADMIN_JWT"
   ```

5. **If full compromise suspected: reshare to new node set**
   - Provision new nodes on clean infrastructure
   - Execute reshare ceremony to new threshold config
   - Decommission old nodes

6. **Notify stakeholders** per compliance requirements

---

## 4. Disaster Recovery — Key Backup Restore

**When:** Loss of a node, data corruption, or full cluster failure.

### Single Node Recovery

```bash
# 1. Provision replacement node
kubectl apply -f infra/k8s/deployment.yaml

# 2. Restore key share backups from encrypted backup
# Key shares are stored in PersistentVolumes with encrypted-ssd StorageClass
# If PV is lost, restore from the last backup:
kubectl cp backup/keys/ mpc-node-$N:/data/keys/

# 3. Verify node health
curl http://mpc-node-$N:3000/v1/health

# 4. Test signing with a non-critical wallet
```

### Full Cluster Recovery

1. Deploy infrastructure: `terraform apply`
2. Deploy NATS: `kubectl apply -f infra/k8s/` (NATS resources)
3. Deploy MPC nodes: `kubectl apply -f infra/k8s/deployment.yaml`
4. Restore key shares from encrypted off-site backup to each node
5. Verify audit ledger integrity: `mpc-wallet-cli audit-verify`
6. Test keygen + sign on testnet before enabling mainnet

### Recovery Time Objectives
| Scenario | RTO | RPO |
|----------|-----|-----|
| Single node failure | 15 min | 0 (PV intact) |
| AZ failure | 30 min | 0 (multi-AZ) |
| Full cluster | 4 hours | Last backup |

---

## 5. Proactive Key Refresh Ceremony

**When:** Scheduled (recommended: monthly) or after any security event.

### Purpose
Generate new key shares while preserving the group public key. Old shares become useless even if previously leaked.

### Steps

1. **Schedule maintenance window** (signing unavailable during refresh)
2. **Notify all parties** of the refresh ceremony
3. **Execute refresh via API:**
   ```bash
   curl -X POST https://api.example.com/v1/wallets/{id}/refresh \
     -H "Authorization: Bearer $ADMIN_JWT"
   ```
4. **Verify:** attempt a test signing to confirm new shares work
5. **Backup new shares** to encrypted off-site storage
6. **Securely delete old share backups** after verification

### Protocols that support refresh:
- GG20 ECDSA (additive re-sharing, preserves group pubkey)
- FROST Ed25519 (DKG-based, preserves group pubkey)
- FROST Secp256k1 (additive re-sharing, preserves group pubkey)

---

## 6. Key Reshare — Change Threshold or Parties

**When:** Adding/removing nodes, changing threshold (e.g., 2-of-3 → 3-of-5).

### Steps

1. **Plan new threshold configuration** (new_t, new_n, new party IDs)
2. **Provision new nodes** if adding parties
3. **Execute reshare:**
   ```bash
   # Via CLI (interactive)
   mpc-wallet-cli reshare \
     --group-id $GROUP_ID \
     --new-threshold 3 \
     --new-parties 5
   ```
4. **Verify new configuration** works with test signing
5. **Decommission removed nodes** if any
6. **Update key metadata** to reflect new threshold

### Important Notes
- GG20 reshare preserves the group public key (wallet addresses unchanged)
- FROST reshare generates a new group key (new addresses — must migrate funds)
- Old shares from removed parties are invalidated

---

## 7. RPC Failover — Manual Provider Switch

**When:** Primary RPC provider experiencing downtime or degraded performance.

### Automatic Failover
The RPC registry automatically fails over to healthy endpoints via `next_healthy_endpoint()`. Monitor via:
```bash
curl http://api.example.com/v1/metrics | grep mpc_rpc
```

### Manual Intervention

```bash
# 1. Check current RPC health
curl http://api.example.com/v1/health

# 2. Update ConfigMap with new RPC endpoints
kubectl edit configmap mpc-config -n mpc-wallet
# Change rpc_provider or add custom endpoints

# 3. Rolling restart to pick up config changes
kubectl rollout restart statefulset/mpc-node -n mpc-wallet

# 4. Verify new endpoints are in use
curl http://api.example.com/v1/metrics | grep rpc_health
```

### Supported RPC Providers
| Provider | Type | Chains |
|----------|------|--------|
| Dwellir | JSON-RPC | EVM, Polkadot, Cosmos, Solana |
| Alchemy | JSON-RPC | EVM (Ethereum, Polygon, Arbitrum, etc.) |
| Infura | JSON-RPC | EVM (Ethereum, Polygon, etc.) |
| Blockstream | REST | Bitcoin |
| Mempool.space | REST | Bitcoin |
| Custom | Any | Any (user-configured) |
