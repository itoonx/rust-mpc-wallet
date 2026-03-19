# SGX Enclave Design Document — DEC-017

> **Status:** Approved (Sprint 23)
> **Author:** R0 Architect
> **Decision:** DEC-017 — Hardware-isolated MPC signing via Intel SGX / TDX

---

## 1. Overview

**Goal:** Hardware-isolated MPC signing computation using Intel SGX (or its successor, Intel TDX).

**Why:** Defense-in-depth. Even if the host OS or hypervisor is compromised, key shares remain
protected inside a hardware enclave. The enclave boundary guarantees that secret scalar values
(`k_i`, `x_i`, `chi_i`) are never exposed to the untrusted host during MPC computation.

This design complements the existing security layers:
- Transport layer: Ed25519-signed envelopes with seq_no replay protection (SEC-007)
- Key storage: AES-256-GCM encryption with Argon2id KDF (SEC-004/005/006)
- Authorization: SignAuthorization with independent node verification (DEC-012)
- Architecture: Gateway holds zero shares, each node holds exactly one (DEC-015)

SGX adds a **hardware root of trust** — the final layer that protects against a compromised
operating system or a malicious cloud operator with physical access to the machine.

---

## 2. Enclave Boundary

### Runs INSIDE the enclave (Trusted Computing Base)

| Component | Rationale |
|-----------|-----------|
| Key share decryption (AES-256-GCM with Argon2id-derived key) | Share plaintext must never exist outside enclave memory |
| MPC signing computation (partial signature generation) | Secret scalars used during computation |
| Secret scalar operations (`k_i`, `x_i`, `chi_i`) | Core MPC secrets — highest sensitivity |
| Zeroization of secrets on completion | Must happen inside enclave before returning |

### Stays OUTSIDE the enclave (Untrusted Host)

| Component | Rationale |
|-----------|-----------|
| Network I/O (NATS transport) | Requires syscalls that SGX cannot perform efficiently |
| Key store file I/O | Enclave reads/writes sealed blobs; host manages filesystem |
| Policy evaluation | No secret material involved; deterministic rule checks |
| Orchestration / session management | Coordination logic, no secrets |
| Logging | No secrets in logs (project invariant); enclave should not log |

**Design principle:** Minimize the Trusted Computing Base (TCB). Only code that touches
secret key material runs inside the enclave. Everything else stays outside to reduce
attack surface and simplify enclave auditing.

---

## 3. Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  OUTSIDE (untrusted host)                                       │
│                                                                 │
│  NATS recv ──► deserialize ProtocolMessage ──► validate sender  │
│                                                    │            │
│                                              ┌─────▼──────┐    │
│                                              │ ECALL       │    │
│  ┌───────────────────────────────────────────┐│             │    │
│  │  INSIDE (SGX enclave)                     ││             │    │
│  │                                           ││             │    │
│  │  1. Unseal encrypted key share            ││             │    │
│  │  2. Decrypt share (AES-256-GCM)           ││             │    │
│  │  3. Compute partial signature             ││             │    │
│  │  4. Zeroize all secret scalars            ││             │    │
│  │  5. Return partial signature bytes        ││             │    │
│  │                                           ││             │    │
│  └───────────────────────────────────────────┘│             │    │
│                                              │ OCALL return │    │
│                                              └─────┬──────┘    │
│                                                    │            │
│  serialize partial sig ──► NATS publish ───────────┘            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Detailed flow:**

1. **Outside:** MPC node receives a NATS message, deserializes the `ProtocolMessage`,
   validates the Ed25519 signed envelope (SEC-007).
2. **Outside:** Node verifies `SignAuthorization` from the gateway (DEC-012).
3. **ECALL (enter enclave):** Pass encrypted share blob + protocol message payload.
4. **Inside:** Unseal the share using SGX sealing key, decrypt with AES-256-GCM.
5. **Inside:** Perform MPC partial signature computation using the decrypted share.
6. **Inside:** Zeroize all secret scalars (`k_i`, `x_i`, `chi_i`, share plaintext).
7. **OCALL (exit enclave):** Return only the partial signature bytes.
8. **Outside:** Serialize the partial signature, publish via NATS.

---

## 4. Attestation Model

### Remote Attestation

Each MPC node proves it is running inside a genuine Intel SGX enclave before participating
in any keygen or signing session.

**Attestation report contents:**

| Field | Description |
|-------|-------------|
| `MRENCLAVE` | SHA-256 hash of the enclave code + data at build time (code identity) |
| `MRSIGNER` | Hash of the enclave signing key (developer identity) |
| `ISV_PROD_ID` | Product identifier assigned by the developer |
| `ISV_SVN` | Security version number (monotonically increasing) |
| `REPORT_DATA` | 64 bytes of user-defined data (used to bind attestation to session) |

### Attestation Protocol

```
1. Session start: orchestrator requests keygen/sign
2. Each MPC node generates a fresh attestation report
   - REPORT_DATA = SHA-256(session_id || node_pubkey || timestamp)
3. Nodes exchange attestation reports via NATS
4. Each node verifies peer reports:
   a. MRENCLAVE matches expected value (pinned in config)
   b. MRSIGNER matches expected developer key
   c. ISV_SVN >= minimum required version
   d. REPORT_DATA binds to current session
5. Gateway verifies all node attestations before issuing SignAuthorization
6. Only after all attestations pass does the MPC protocol proceed
```

### Attestation Backends

| Backend | Use Case | Intel Dependency |
|---------|----------|------------------|
| EPID (Enhanced Privacy ID) | Legacy SGX1 hardware | Requires Intel Attestation Service (IAS) |
| DCAP (Data Center Attestation Primitives) | Modern SGX2 / TDX | No Intel dependency; uses local PCCS cache |

**Recommendation:** Target DCAP for production. EPID support is optional for legacy
hardware compatibility. The `EnclaveProvider` trait abstracts over both backends.

---

## 5. Gramine Framework

### Why Gramine

[Gramine](https://gramine.readthedocs.io/) (formerly Graphene) allows running **unmodified
Linux binaries** inside SGX enclaves. This means the existing Rust MPC node binary can run
inside an enclave without rewriting it in an SGX-specific SDK.

**Advantages over raw SGX SDK:**
- No code rewrite needed — existing `mpc-node` binary runs as-is
- Standard Rust toolchain (no special compiler)
- Active open-source community with enterprise adoption
- Supports file I/O, networking, and threading through shims

### Manifest Template

The Gramine manifest (`mpc-node.manifest.template`) defines the enclave configuration:

```toml
[loader]
entrypoint = "file:mpc-node"
argv0_override = "mpc-node"

[libos]
entrypoint = "/usr/lib/x86_64-linux-gnu/gramine/libsysdb.so"

[sys]
insecure__allow_eventfd = true  # required for tokio async runtime
stack_size = "2M"

[sgx]
enclave_size = "512M"           # must fit key shares + MPC computation
thread_num = 8                  # async runtime threads
debug = false                   # MUST be false in production
isvprodid = 1
isvsvn = 1

# Trusted files: integrity-checked at load time
[[sgx.trusted_files]]
uri = "file:mpc-node"

[[sgx.trusted_files]]
uri = "file:/lib/x86_64-linux-gnu/"

# Allowed files: enclave can read/write but not integrity-checked
[[sgx.allowed_files]]
uri = "file:/data/keystore/"    # encrypted key shares (sealed separately)

[[sgx.allowed_files]]
uri = "file:/tmp/"              # tokio runtime temporary files
```

### Build Process

```bash
# 1. Build the mpc-node binary (standard Rust)
cargo build --release -p mpc-node

# 2. Generate Gramine manifest from template
gramine-manifest \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    mpc-node.manifest.template \
    mpc-node.manifest

# 3. Sign the enclave (produces SIGSTRUCT with MRENCLAVE)
gramine-sgx-sign \
    --manifest mpc-node.manifest \
    --key enclave-signing-key.pem \
    --output mpc-node.manifest.sgx

# 4. Generate SGX token (for launch)
gramine-sgx-get-token \
    --sig mpc-node.sig \
    --output mpc-node.token

# 5. Run inside enclave
gramine-sgx mpc-node -- --party-id 1 --nats-url nats://...
```

### Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Enclave heap limited (default 256MB, max ~4GB) | Large key groups may not fit | Set `enclave_size = "512M"`; monitor memory usage |
| No `fork()` support | Cannot spawn child processes | Use threads only (tokio runtime is fine) |
| Limited threading (fixed at enclave init) | Thread pool size is static | Set `thread_num = 8` to match tokio default |
| File I/O goes through Gramine shim | Slight performance overhead | Acceptable for key store operations |
| `RDRAND` instruction required | Entropy source for crypto | Available on all SGX-capable CPUs |

---

## 6. Threat Model

### What SGX Protects Against

| Threat | Protection Mechanism |
|--------|---------------------|
| Malicious cloud operator reading memory | Enclave memory is encrypted by CPU; host OS cannot read it |
| OS-level rootkit extracting key shares | Key shares exist in plaintext only inside enclave |
| Cold boot attacks on DRAM | Memory Encryption Engine (MEE) encrypts enclave pages |
| Hypervisor-level memory introspection | SGX isolation is below hypervisor level |
| DMA attacks (Thunderbolt, PCIe) | Enclave memory excluded from DMA-accessible regions |
| Malicious co-tenant on shared hardware | Each enclave has isolated memory region |

### What SGX Does NOT Protect Against

| Threat | Why Not | Mitigation |
|--------|---------|------------|
| Side-channel attacks (Spectre, Foreshadow, LVI, AEPIC) | Microarchitectural leakage bypasses enclave boundary | Keep CPU microcode updated; use constant-time crypto; consider TDX (which mitigates many of these) |
| Denial of service | Operator can kill the enclave process | Threshold architecture (t-of-n) tolerates node loss |
| Supply chain compromise | Malicious enclave code passes attestation | Code audit + reproducible builds + MRENCLAVE pinning |
| Rollback attacks on sealed data | Attacker replays old sealed state | Monotonic counter (SGX trusted counter) + external consistency check |
| Controlled-channel attacks | OS controls page tables, can observe access patterns | ORAM-based access patterns (future work) |
| Physical decapping of CPU | Extremely expensive but theoretically possible | Out of scope; assumes Intel CPU tamper resistance |

### Residual Risk Assessment

SGX is a **defense-in-depth layer**, not a silver bullet. The MPC wallet's security does not
depend solely on SGX. Even without SGX, the system provides:
- Threshold signing (no single party holds the full key)
- Encrypted key storage (AES-256-GCM + Argon2id)
- Authenticated transport (Ed25519 signed envelopes)
- Independent authorization verification (SignAuthorization)

SGX adds hardware isolation as an **additional** barrier. If SGX is compromised, the other
layers remain intact.

---

## 7. Key Management Inside Enclave

### Sealing

SGX provides **sealing** — encrypting data to the enclave identity so that only the same
enclave (on the same CPU) can decrypt it.

```
Seal Key = CPU_Root_Key + MRENCLAVE + KEY_POLICY
```

| Sealing Policy | Binds To | Use Case |
|----------------|----------|----------|
| `MRENCLAVE` | Exact enclave code hash | Strictest; any code change invalidates sealed data |
| `MRSIGNER` | Developer signing key | Allows enclave upgrades by same developer |

**Recommendation:** Use `MRSIGNER` policy for sealed key shares. This allows enclave binary
upgrades without re-sealing all key shares, while still binding to the developer identity.

### Key Share Lifecycle

```
1. KEYGEN (inside enclave):
   - MPC keygen produces share_i (secret scalar)
   - Enclave seals share_i → sealed_blob
   - sealed_blob written to disk (encrypted at rest via SGX + AES-256-GCM double layer)

2. SIGN (inside enclave):
   - Read sealed_blob from disk
   - Unseal → share_i plaintext (only in enclave memory)
   - Compute partial signature using share_i
   - Zeroize share_i
   - Return partial signature

3. REFRESH (inside enclave):
   - Unseal old share → old_share_i
   - Participate in refresh protocol → new_share_i
   - Seal new_share_i → new_sealed_blob
   - Zeroize old_share_i, new_share_i
   - Write new_sealed_blob, delete old
```

### Enclave Upgrade Migration

When the enclave binary is updated (new `MRENCLAVE`), sealed data from the old enclave
cannot be read by the new one (under `MRENCLAVE` policy). Migration path:

```
1. Deploy new enclave version alongside old version
2. Old enclave unseals share → passes to new enclave via local attestation channel
3. New enclave verifies old enclave's attestation (same MRSIGNER)
4. New enclave re-seals share under its own MRENCLAVE
5. Old enclave zeroizes and shuts down
6. Delete old sealed blobs
```

Under `MRSIGNER` policy, this migration is unnecessary (shares survive upgrades), but
`ISV_SVN` must be monotonically increasing to prevent rollback to older enclave versions.

---

## 8. Implementation Phases

### Phase 1: Sprint 23 (Current) — Mock Enclave + Trait Definition

**Deliverables:**
- `EnclaveProvider` trait in `crates/mpc-wallet-core/src/enclave/mod.rs`
- `AttestationReport` and `EnclaveHandle` types
- Feature-gated mock implementation (`#[cfg(any(test, feature = "mock-enclave"))]`)
- This design document (`docs/SGX_DESIGN.md`)

**What the mock does:**
- `load_share()`: decrypts share in normal memory (no SGX)
- `sign()`: delegates to existing MPC protocol code
- `attestation_report()`: returns a synthetic report with known MRENCLAVE
- Allows integration testing of the enclave API without SGX hardware

### Phase 2 (Future) — Gramine Integration

**Deliverables:**
- Gramine manifest template for `mpc-node`
- Build scripts for `gramine-sgx-sign`
- Real `GramineEnclaveProvider` implementation
- Integration tests on SGX-enabled CI runners (Azure DCsv3, AWS Nitro Enclaves)
- DCAP attestation verification library integration

**Prerequisites:**
- Access to SGX-capable hardware (Intel Xeon Scalable 3rd gen+)
- PCCS (Provisioning Certification Caching Service) deployment
- Enclave signing key management (HSM-stored)

### Phase 3 (Future) — Production Deployment

**Deliverables:**
- DCAP attestation in production MPC node startup
- Attestation report exchange wired into NATS control plane
- Gateway attestation verification before `SignAuthorization` issuance
- Sealed key share migration tooling
- Monitoring: enclave health metrics, attestation freshness
- Runbook: enclave upgrade procedures, sealed data migration

---

## 9. API Surface

### Trait Definition

```rust
/// Handle to a loaded key share inside the enclave.
/// Opaque to callers — the actual share plaintext never leaves the enclave.
pub struct EnclaveHandle {
    pub id: String,
}

/// SGX/TDX remote attestation report.
pub struct AttestationReport {
    /// SHA-256 hash of the enclave code + initial data (code identity).
    pub mrenclave: [u8; 32],
    /// SHA-256 hash of the enclave signing key (developer identity).
    pub mrsigner: [u8; 32],
    /// Product identifier assigned by the developer.
    pub isv_prod_id: u16,
    /// Security version number (monotonically increasing).
    pub isv_svn: u16,
    /// User-defined data bound to the attestation (64 bytes in SGX).
    pub report_data: Vec<u8>,
    /// Raw attestation report bytes (EPID or DCAP format).
    pub raw_report: Vec<u8>,
}

/// Partial signature produced inside the enclave.
pub struct PartialSignature {
    pub party_id: PartyId,
    pub data: Vec<u8>,
}

/// Abstraction over SGX/TDX enclave operations for MPC signing.
///
/// Implementations:
/// - `MockEnclaveProvider` (feature = "mock-enclave") — no hardware, for testing
/// - `GramineEnclaveProvider` (future) — real SGX via Gramine framework
///
/// The enclave boundary ensures that key share plaintext and secret scalars
/// never exist in host memory. Only opaque handles and partial signatures
/// cross the enclave boundary.
#[async_trait]
pub trait EnclaveProvider: Send + Sync {
    /// Load an encrypted key share into the enclave.
    ///
    /// The share is decrypted inside the enclave using the provided password.
    /// Returns an opaque handle; the plaintext share never leaves the enclave.
    async fn load_share(
        &self,
        encrypted_share: &[u8],
        password: &[u8],
    ) -> Result<EnclaveHandle, CoreError>;

    /// Compute a partial signature inside the enclave.
    ///
    /// Uses the key share referenced by `handle` to compute a partial
    /// signature over `message`. The secret scalar is zeroized after use.
    async fn sign(
        &self,
        handle: &EnclaveHandle,
        message: &[u8],
    ) -> Result<PartialSignature, CoreError>;

    /// Retrieve the enclave's remote attestation report.
    ///
    /// The report proves that this code is running inside a genuine SGX enclave.
    /// Callers should verify `mrenclave` and `mrsigner` against pinned values.
    fn attestation_report(&self) -> Result<AttestationReport, CoreError>;

    /// Destroy a loaded key share, zeroizing all enclave-side state.
    ///
    /// After this call, the handle is invalid and must not be reused.
    fn destroy(&self, handle: EnclaveHandle);
}
```

### Integration Points

| Component | Integration |
|-----------|------------|
| `mpc-node` (`services/mpc-node/`) | Uses `EnclaveProvider` instead of direct `KeyStore::load` + protocol calls |
| `KeyStore` trait | Provides encrypted share blobs to `EnclaveProvider::load_share()` |
| `SignAuthorization` | Verified **outside** enclave before ECALL (no change needed) |
| `NatsTransport` | Stays outside enclave; passes payloads to/from ECALL boundary |
| `MpcProtocol` trait | Signing computation moves inside enclave; trait itself unchanged |

### Feature Gates

```toml
[features]
mock-enclave = []   # Mock EnclaveProvider for testing without SGX hardware
sgx-gramine = []    # Real Gramine SGX integration (Phase 2)
```

---

## 10. References

- [Intel SGX Developer Reference](https://download.01.org/intel-sgx/sgx-linux/2.23/docs/)
- [Gramine Documentation](https://gramine.readthedocs.io/en/stable/)
- [DCAP Attestation](https://download.01.org/intel-sgx/sgx-dcap/1.20/linux/docs/)
- DEC-012: Sign Authorization (independent node verification)
- DEC-015: Gateway/node split (each node holds exactly 1 share)
- SEC-004/008: Key share and scalar zeroization patterns
