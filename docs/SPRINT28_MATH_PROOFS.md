# Sprint 28 Mathematical Proofs

> **Purpose:** Formal correctness proofs for the Paillier-based MtA and ZK proof
> integration into CGGMP21/GG20 protocols. Written BEFORE implementation per
> project rule: "Prove crypto math on paper BEFORE implementing."

---

## Notation

| Symbol | Definition |
|--------|-----------|
| `N = p * q` | Paillier modulus (safe primes, `p = 2p' + 1`, `q = 2q' + 1`) |
| `lambda = lcm(p-1, q-1)` | Carmichael function of N |
| `Enc(m, r)` | Paillier encryption: `(1 + mN) * r^N mod N^2` |
| `Dec(c)` | Paillier decryption: `L(c^lambda mod N^2) * mu mod N` |
| `L(x)` | `(x - 1) / N` |
| `G` | secp256k1 generator point |
| `q_ec` | secp256k1 group order (`~2^256`) |
| `(N_hat, s, t)` | Pedersen commitment parameters |
| `ell = 256` | Range parameter (secp256k1 scalar bit-length) |
| `epsilon = 512` | Statistical slack parameter |
| `H(...)` | SHA-256 hash (Fiat-Shamir oracle) |

---

## Proof 1: MtA (Multiplicative-to-Additive) Correctness

### Statement

Given Party A with secret `a` and Paillier keypair `(pk_A, sk_A)`, and Party B
with secret `b`, the MtA protocol produces shares `alpha` (held by A) and
`beta` (held by B) such that:

```
alpha + beta = a * b   (mod N)
```

### Protocol

1. **A -> B:** `c_A = Enc_A(a, r_a)` where `r_a` is random in `Z*_N`
2. **B computes:**
   - `c_ab = c_A^b mod N^2` (homomorphic scalar mult)
   - Samples `beta' in [0, N)` uniformly at random
   - `c_neg_beta = Enc_A(N - beta', r_b)` for random `r_b`
   - `c_B = c_ab * c_neg_beta mod N^2` (homomorphic addition)
   - Sets `beta = beta'`
3. **B -> A:** `c_B`
4. **A computes:** `alpha = Dec_A(c_B)`

### Proof

By Paillier homomorphic properties:

**Step 2a:** `c_ab = c_A^b = Enc(a, r_a)^b = Enc(a*b, r_a^b)` (scalar mult property).

*Proof of scalar mult:*
```
c_A^b = ((1 + a*N) * r_a^N)^b  mod N^2
      = (1 + a*N)^b * r_a^(bN)  mod N^2
```
By binomial expansion (terms with `N^k` for `k >= 2` vanish mod `N^2`):
```
(1 + a*N)^b = 1 + a*b*N  mod N^2
```
Therefore: `c_A^b = (1 + a*b*N) * (r_a^b)^N mod N^2 = Enc(a*b, r_a^b)`.

**Step 2b-2c:** `c_neg_beta = Enc(N - beta', r_b)`.

In `Z_N`, `N - beta' = -beta' mod N`, so this encrypts `-beta'`.

**Step 2d:** By additive homomorphism:
```
c_B = c_ab * c_neg_beta  mod N^2
    = Enc(a*b, r_a^b) * Enc(-beta', r_b)  mod N^2
    = Enc(a*b + (-beta'), r_combined)  mod N^2
    = Enc(a*b - beta', r_combined)
```

where `r_combined = r_a^b * r_b mod N`.

*Proof of additive homomorphism:*
```
Enc(m1, r1) * Enc(m2, r2)
  = ((1 + m1*N) * r1^N) * ((1 + m2*N) * r2^N)  mod N^2
  = (1 + m1*N)(1 + m2*N) * (r1*r2)^N  mod N^2
  = (1 + (m1 + m2)*N + m1*m2*N^2) * (r1*r2)^N  mod N^2
  = (1 + (m1 + m2)*N) * (r1*r2)^N  mod N^2
  = Enc(m1 + m2, r1*r2)
```

**Step 4:** `alpha = Dec(c_B) = a*b - beta' mod N`.

**Result:** `alpha + beta = (a*b - beta') + beta' = a*b mod N`. QED.

### No-Wrapping Condition

For correctness in the integer ring (not just modular), we need `a*b < N`.
Since `a, b < q_ec ~ 2^256` and `N >= 2^1024` (test) or `N >= 2^2048` (prod):
```
a * b < 2^256 * 2^256 = 2^512 << 2^1024 <= N
```
Therefore no modular wrapping occurs, and `alpha + beta = a*b` exactly as integers.

---

## Proof 2: Pienc (Paillier Encryption Range Proof) Soundness

### Statement

If verifier accepts `PiEncProof`, then prover knows `(m, r)` such that
`C = Enc(m, r)` with `|m| < 2^ell` (where `ell = 256`).

### Construction (Sigma Protocol + Fiat-Shamir)

**Prover** (knows witness `m, r, rho`):
1. Sample: `alpha <- [0, 2^(ell+epsilon))`, `mu <- Z*_N`, `gamma <- [0, N_hat * 2^768)`, `rho <- [0, N_hat * 2^256)`
2. Compute commitments:
   - `A = Enc(alpha, mu)`
   - `B = s^alpha * t^gamma mod N_hat`
   - `S = s^m * t^rho mod N_hat`
3. Challenge: `e = H("pienc-v1" || N || C || A || B || S || N_hat)` (128 bits)
4. Responses:
   - `z1 = alpha + e*m`
   - `z2 = mu * r^e mod N^2`
   - `z3 = gamma + e*rho`

**Verifier** checks:
1. `z1 < 2^(ell+epsilon)` (range check)
2. `Enc(z1, z2) = A * C^e mod N^2` (Paillier consistency)
3. `s^z1 * t^z3 = B * S^e mod N_hat` (Pedersen consistency)

### Proof of Soundness

**Special soundness (knowledge extraction):** Given two accepting transcripts
`(A, B, S, e, z1, z2, z3)` and `(A, B, S, e', z1', z2', z3')` with `e != e'`:

From Paillier check: `Enc(z1, z2) * C^(-e) = A = Enc(z1', z2') * C^(-e')`

This gives: `Enc(z1 - z1', z2/z2') = C^(e - e')` in the ciphertext space.

Since `e - e' != 0` and is invertible (small enough), we can extract:
```
m = (z1 - z1') / (e - e')
r = (z2 / z2')^(1/(e-e')) mod N
```

From Pedersen check: `s^(z1-z1') * t^(z3-z3') = S^(e-e')`, confirming consistency.

**Range guarantee:** Since `alpha < 2^(ell+epsilon)` and `|e*m| < 2^128 * 2^ell`:
```
z1 = alpha + e*m < 2^(ell+epsilon) + 2^(128+ell) = 2^768 + 2^384 ~ 2^768
```

The verifier checks `z1 < 2^768`. If `|m| >= 2^ell`, then:
```
|e*m| >= 2^(128+ell) = 2^384
```
But `alpha < 2^768`, so `z1 = alpha + e*m` could be in range only if
`alpha` and `e*m` happen to cancel. The statistical distance from a cheating
prover to an honest one is bounded by `2^(-epsilon) = 2^(-512)`, which is
negligible. Therefore the proof is sound with overwhelming probability. QED.

### Zero-Knowledge

The simulator, knowing only `(C, e)`, can simulate `(A, B, S, z1, z2, z3)` by:
1. Choose `z1, z2, z3` uniformly in their ranges
2. Compute `A = Enc(z1, z2) * C^(-e)`, `B = s^z1 * t^z3 * S^(-e) mod N_hat`

The distribution is statistically close to real transcripts (slack `epsilon`
absorbs the difference). QED.

---

## Proof 3: Piaffg (Affine Operation Range Proof) Soundness

### Statement

If verifier accepts `PiAffgProof`, then prover knows `(x, y, rho_y)` such that
`D = C^x * Enc(y, rho_y) mod N_0^2` with `|x|, |y| < 2^ell`.

### Construction

**Prover** (knows `x, y, rho_y, tau, sigma`):
1. Sample masking: `alpha, beta <- [0, 2^(ell+epsilon))`, `mu <- Z*_{N_0}`,
   `gamma, delta <- [0, N_hat * 2^768)`, `tau, sigma <- [0, N_hat * 2^256)`
2. Commitments:
   - `A = C^alpha * Enc(beta, mu) mod N_0^2`
   - `E = s^alpha * t^gamma mod N_hat` (Pedersen for x)
   - `F = s^beta * t^delta mod N_hat` (Pedersen for y)
   - `S_x = s^x * t^tau mod N_hat`
   - `S_y = s^y * t^sigma mod N_hat`
3. Challenge: `e = H("piaffg-v1" || N_0 || C || D || A || E || F || S_x || S_y || N_hat)`
4. Responses:
   - `z1 = alpha + e*x`, `z2 = beta + e*y`
   - `w = mu * rho_y^e mod N_0^2`
   - `z3 = gamma + e*tau`, `z4 = delta + e*sigma`

**Verifier** checks:
1. `z1, z2 < 2^(ell+epsilon)`
2. `C^z1 * Enc(z2, w) = A * D^e mod N_0^2`
3. `s^z1 * t^z3 = E * S_x^e mod N_hat`
4. `s^z2 * t^z4 = F * S_y^e mod N_hat`

### Proof of Soundness

**Knowledge extraction:** From two transcripts with `e != e'`:

Check 2 gives:
```
C^(z1-z1') * Enc(z2-z2', w/w') = D^(e-e')  mod N_0^2
```

Since `D = C^x * Enc(y, rho_y)`:
```
C^(z1-z1') * Enc(z2-z2', w/w') = C^(x*(e-e')) * Enc(y*(e-e'), rho_y^(e-e'))
```

Matching powers of C: `z1 - z1' = x * (e - e')`, so `x = (z1 - z1') / (e - e')`.

Matching Enc terms: `z2 - z2' = y * (e - e')`, so `y = (z2 - z2') / (e - e')`.

**Range:** Same argument as Pienc, extended to two dimensions. The verifier
checks `z1, z2 < 2^768`, and the statistical slack `epsilon = 512` ensures
that `|x|, |y| < 2^256` with overwhelming probability. QED.

---

## Proof 4: Pilogstar (Paillier/EC Point Consistency) Soundness

### Statement

If verifier accepts `PiLogStarProof`, then prover knows `(x, r)` such that
`C = Enc(x, r)` AND `X = x * G` on secp256k1, with `|x| < 2^ell`.

### Construction

**Prover** (knows `x, r, rho`):
1. Sample: `alpha <- [0, 2^(ell+epsilon))`, `mu <- Z*_N`, `gamma <- [0, N_hat * 2^768)`
2. Commitments:
   - `A = Enc(alpha, mu)`
   - `Y = alpha * G` (secp256k1 point)
   - `D = s^alpha * t^gamma mod N_hat`
3. Challenge: `e = H("pilogstar-v1" || N || C || X || A || Y || D || N_hat)`
4. Responses: `z1 = alpha + e*x`, `z2 = mu * r^e mod N^2`, `z3 = gamma + e*rho`

**Verifier** checks:
1. `z1 < 2^(ell+epsilon)` (range)
2. `Enc(z1, z2) = A * C^e mod N^2` (Paillier)
3. `z1 * G == Y + e * X` (EC point equation)
4. `s^z1 * t^z3 = D * S^e mod N_hat` (Pedersen)

### Proof of Soundness

**EC binding:** Check 3 verifies:
```
z1 * G = Y + e * X
(alpha + e*x) * G = alpha*G + e*(x*G)
alpha*G + e*x*G = alpha*G + e*x*G  (trivially true for honest prover)
```

**Knowledge extraction:** From two transcripts:
- EC check: `(z1-z1')*G = (e-e')*X`, so `X = ((z1-z1')/(e-e')) * G`
- Paillier check: `Enc(z1-z1', z2/z2') = C^(e-e')`, extracting same `x`

**Cross-system binding:** The same value `x = (z1-z1')/(e-e')` satisfies
BOTH `C = Enc(x, r)` and `X = x*G`. An adversary cannot use different `x`
values for Paillier and EC because both extractions derive `x` from the same
`z1, z1', e, e'` values. QED.

---

## Proof 5: Pedersen Parameter Generation

### Construction

Generate Pedersen parameters `(N_hat, s, t)`:

1. Generate safe primes `p_hat = 2*p_hat' + 1`, `q_hat = 2*q_hat' + 1`
2. Set `N_hat = p_hat * q_hat`
3. Choose `s` uniformly from `Z*_{N_hat}`
4. Choose `lambda` uniformly from `[0, phi(N_hat)/4)`
   where `phi(N_hat) = (p_hat - 1)(q_hat - 1) = 4 * p_hat' * q_hat'`
5. Set `t = s^lambda mod N_hat`

### Hiding Property

**Claim:** Pedersen commitment `Com(m; r) = s^m * t^r mod N_hat` is
statistically hiding.

**Proof:** For any message `m`, the commitment `s^m * t^r = s^(m + lambda*r) mod N_hat`.
The exponent is `m + lambda*r` where `r` is uniform in `[0, ord(s))`.
Since `lambda` is secret and `r` is fresh randomness, the exponent
`m + lambda*r mod ord(s)` is nearly uniform over `Z_{ord(s)}` for any fixed `m`.
Therefore `Com(m; r)` is statistically close to uniform for all `m`. QED.

### Binding Property

**Claim:** Finding `(m, r) != (m', r')` with `Com(m; r) = Com(m'; r')` is hard
under the factoring assumption on `N_hat`.

**Proof:** If `s^m * t^r = s^{m'} * t^{r'} mod N_hat`, then:
```
s^(m - m') = t^(r' - r) = s^(lambda*(r'-r))  mod N_hat
```
So `m - m' = lambda * (r' - r) mod ord(s)`.

If `r' - r != 0`, we get `lambda = (m - m') * (r' - r)^(-1) mod ord(s)`.
But `lambda` determines `t = s^lambda`, and knowing `lambda` with `ord(s)`
reveals the group order, which factors `N_hat`. Under the factoring assumption,
this is computationally infeasible. QED.

---

## Proof 6: End-to-End CGGMP21 Signing Correctness

### Setup (Keygen Output)

After 4-round keygen, each party `i` holds:
- Secret share `x_i` (Feldman VSS)
- Group public key `X = x * G` where `x = sum(x_j * lambda_j)` over all parties
- Paillier keypair `(pk_i, sk_i)` verified by Pimod + Pifac
- Pedersen parameters `(N_hat, s, t)` per party

### Pre-Signing (Offline)

**Goal:** Produce `PreSignature = (k_i, chi_i, delta_i, R)` such that:
- `R = k^(-1) * G` where `k = sum(k_i)`
- `chi_i` are shares of `k * x` (using Lagrange coefficients)

**Round 1:** Each party `i`:
- Samples `k_i, gamma_i <- Z_{q_ec}`
- Broadcasts `K_i = k_i * G`, `Gamma_i = gamma_i * G` with Schnorr proofs

**Round 2 (MtA):** For each pair `(i, j)`:
1. Party i encrypts: `c_i = Enc_i(k_i, r_i)` with Pienc proof
2. Party j computes MtA: `alpha_ij + beta_ij = k_i * gamma_j` with Piaffg proof
3. Similarly for chi: `alpha'_ij + beta'_ij = k_i * (x_j * lambda_j)`

**Correctness of delta aggregation:**
```
delta_i = k_i * gamma_i + sum_{j!=i}(alpha_delta_ij + beta_delta_ij)
```

Summing over all parties:
```
sum(delta_i) = sum(k_i * gamma_i) + sum_{i} sum_{j!=i}(alpha_ij + beta_ij)
```

By MtA correctness (Proof 1): `alpha_ij + beta_ij = k_i * gamma_j` for each pair.

```
sum(delta_i) = sum_i(k_i * gamma_i) + sum_i sum_{j!=i}(k_i * gamma_j)
             = sum_i k_i * (gamma_i + sum_{j!=i} gamma_j)
             = sum_i k_i * sum_j gamma_j
             = sum_i k_i * gamma
             = k * gamma
```

where `k = sum(k_i)` and `gamma = sum(gamma_j)`.

**R computation:**
```
Gamma_sum = sum(Gamma_i) = sum(gamma_i * G) = gamma * G
R = delta^(-1) * Gamma_sum = (k * gamma)^(-1) * gamma * G = k^(-1) * G
```

This is the correct ECDSA `R` point. QED.

### Online Signing (1-Round)

**Each party computes:**
```
sigma_i = k_i * e + chi_i * r   (mod q_ec)
```

where:
- `e = SHA256(message)` reduced to scalar
- `r = R.x mod q_ec`
- `chi_i` is party i's share of `k * x`

**Aggregation:**
```
s = sum(sigma_i)
  = sum(k_i * e + chi_i * r)
  = e * sum(k_i) + r * sum(chi_i)
  = e * k + r * k * x
  = k * (e + x * r)
```

**ECDSA verification:** Given public key `X = x*G` and signature `(r, s)`:
```
s^(-1) * (e*G + r*X) = (k*(e+xr))^(-1) * (e*G + r*x*G)
                      = k^(-1) * (e+xr)^(-1) * (e + xr) * G
                      = k^(-1) * G
                      = R
```

So `R.x = r`, which is exactly the ECDSA verification equation. QED.

### ZK Proof Chain

Each ZK proof prevents a specific attack at its step:

| Step | Proof | Prevents |
|------|-------|----------|
| Keygen | Pimod | Malicious N (not Blum modulus) |
| Keygen | Pifac | Small-factor N (CVE-2023-33241) |
| Pre-sign Round 2 | Pienc | Out-of-range k_i (bias R point) |
| MtA Round 2 | Piaffg | Wrong affine computation (corrupt delta shares) |
| Pre-sign Round 2 | Pilogstar | Enc(k_i) != k_i*G mismatch (substitution attack) |

**Identifiable abort:** Every ZK proof verification failure identifies the
cheating party by `party_index`, enabling honest parties to exclude the
adversary and re-run the protocol.

---

## Parameter Choices

| Parameter | Value | Justification |
|-----------|-------|---------------|
| `ell` | 256 | secp256k1 scalar bit-length |
| `epsilon` | 512 | Statistical slack: `2^(-512)` soundness gap |
| `PIMOD_SECURITY_PARAM` | 80 | `2^(-80)` false acceptance for Blum check |
| `PIFAC_ROUNDS` | 40 | `2^(-40)` for Nth root + trial division |
| `PIFAC_MIN_FACTOR_BITS` | 256 | CVE-2023-33241: factors must be >= 256 bits |
| Fiat-Shamir challenge | 128 bits | Collision resistance for interactive-to-NIZK |
| Paillier N (test) | 1024 bits | Adequate for `a*b < 2^512 << 2^1024` |
| Paillier N (prod) | 2048 bits | NIST recommendation for RSA-equivalent security |
| Pedersen N_hat | same as N | Independent safe-prime product for Pedersen |
