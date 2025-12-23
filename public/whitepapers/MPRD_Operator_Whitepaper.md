# MPRD Operator Whitepaper
## Control Plane Invariants for Autonomous AI Infrastructure

**Version 1.1 | December 2025**

---

## 1. The Problem: Safety Without Liveness

MPRD (Model Proposes, Rules Decide) guarantees **safety** via the Alignment Theorem—no unauthorized action executes. But safety alone enables *safe stalls*. Production systems require **liveness**: valid actions must execute within bounded time.

```
Safety:  ∀p,s,a. ExecCalled(p,s,a) ⟹ Allowed(p,s,a)   ✓ Proven
Liveness: ∀p,s,a. Allowed(p,s,a) ⟹ ◇≤Δt ExecCalled     ← This paper
```

**Why now?** As AI systems gain autonomy (ACCOs: Autonomous Continuous Computational Operators), operator infrastructure must have formal guarantees—not just best-effort SLAs.

---

## 2. Threat Model

### Fault Model: Crash-Stop vs Byzantine
| Model | Assumption | Coverage |
|-------|------------|----------|
| **Crash-stop** | Operators fail silently | O2 failover |
| **Byzantine (limited)** | Up to f < n/3 malicious | O9 threshold |
| **Bribery** | Rational operators maximizing utility | O6 economics |

### Adversary Capabilities
| Threat | Covered By | Mitigation |
|--------|-----------|------------|
| Operator stalls valid actions | O2 | Δt timeout + automatic failover |
| Replay attacks | O7 | Single-use nonce registry |
| Unauthorized ops | O1 | On-chain policy verification |
| Audit tampering | O4 | Append-only Merkle log |
| Unilateral high-impact ops | O9 | k-of-n threshold signatures |
| Resource exhaustion | O8 | Hard resource caps |
| Network partition | O2 + consensus | Leader election + view change |
| Equivocation | O4 + O7 | Signed audit + nonce binding |
| Key compromise | O5 + O9 | Short-lived tokens + threshold |

### Out of Scope
- Cryptographic breaks (assumed secure)
- Policy bugs (handled by Tau verification)
- 51% attacks on underlying consensus layer

---

## 3. Architecture: Data Plane vs Control Plane

```
┌─────────────────────────────────────────────────────────────┐
│                    MPRD PIPELINE                            │
├─────────────────────────────────────────────────────────────┤
│  Model Proposes → Verifier Checks → Executor Runs           │
│       (AI)           (Tau Policy)    (Side Effects)         │
├─────────────────────────────────────────────────────────────┤
│                   CONTROL PLANE (O1-O9)                     │
│  Operator → Token → Auth → Execute → Audit                  │
│    ↓          ↓       ↓        ↓        ↓                   │
│   O1,O3      O5,O7   O9       O8       O4                   │
└─────────────────────────────────────────────────────────────┘
```

### Pipeline Flow
```
1. Operator requests action → policy_check(op)         [O1: Must be Allowed_op]
2. Token minted           → mint_token(op, expiry)     [O5: Time-bounded]
3. Token validated        → verify_fresh(token)        [O7: Anti-replay]
4. High-impact check      → threshold_sign(k=3, n=5)   [O9: Multi-party]
5. Execute                → run_bounded(op, R_MAX)     [O8: Resource limit]
6. Audit commit           → append_merkle(op, proof)   [O4: Immutable log]
```

---

## 4. Core Types and Enforcement

```rust
/// Operator action with cryptographic binding
pub struct OperatorAction {
    pub id: ActionId,
    pub op_type: OpType,              // Route, Throttle, Pause, Scale, Rotate
    pub operator: PublicKey,
    pub token: OpToken,
    pub signatures: Vec<Signature>,   // For O9 threshold
    pub resources_required: u64,
}

/// Time-bounded, single-use token
pub struct OpToken {
    pub nonce: [u8; 32],              // Unique per action
    pub issued_at: u64,
    pub expires_at: u64,              // O5 enforcement
    pub action_hash: Hash,            // Binds to specific action
}

/// Pipeline execution with all invariants
pub fn execute_action(op: OperatorAction) -> Result<(), OperatorError> {
    // Verify action_hash binds token to this specific action
    let computed_hash = hash(&op.id, &op.op_type, &op.operator);
    if computed_hash != op.token.action_hash {
        return Err(OperatorError::HashMismatch);
    }
    
    // O1: Policy-bound
    if !policy.allows(&op) {
        return Err(OperatorError::NotAllowed);
    }
    
    // O5: Token not expired
    if now() > op.token.expires_at {
        return Err(OperatorError::TokenExpired);
    }
    
    // O7: Token is fresh (anti-replay via replicated registry)
    // TOKEN_REGISTRY is consensus-replicated across all validators
    if !TOKEN_REGISTRY.try_consume(&op.token.nonce) {
        return Err(OperatorError::ReplayDetected);
    }
    
    // Verify operator signature over token
    if !verify_sig(&op.operator, &op.token, &op.signatures[0]) {
        return Err(OperatorError::InvalidSignature);
    }
    
    // O9: High-impact requires threshold
    if op.is_high_impact() {
        verify_threshold(&op.signatures, K, N)?;
    }
    
    // O8: Resource bounds
    if op.resources_required > R_MAX {
        return Err(OperatorError::ResourceExceeded);
    }
    
    // Execute the operation (atomic with audit)
    let result = execute(op.clone());
    
    // O4: Immutable audit (always, even on failure)
    // Audit and execution are atomic: both commit or neither
    AUDIT_LOG.append_atomic(AuditRecord {
        action: op,
        result: result.clone(),
        timestamp: now(),
        merkle_proof: compute_proof(),
    })?;
    
    result
}
```

---

## 5. Liveness Guarantee (O2)

### Formal Specification
```
Assumptions:
  - Weak fairness: Continuously enabled actions eventually execute
  - Fault model: Crash-stop (no Byzantine operators)
  - Detection: Crashed operators detected within δ time

Guarantee (LTL):
  □[(∃a. Allowed(p,s,a)) ∧ OperatorActive ∧ ¬Crashed]
    ⟹ ◇≤Δt ExecCalled(p,s,a*)

Where:
  Δt = max(processing_time, consensus_delay, failover_time)
  Δt_max = 10s (configurable per deployment)
```

### Adversarial Scenario: Stalling Attack
1. **Attack**: Malicious operator delays all valid actions
2. **Detection**: Watchdog timer triggers at Δt
3. **Response**: 
   - O6 slashes operator stake
   - Failover to backup operator
   - Actions resume within Δt_max

---

## 6. Economic Mechanism Design

### Stake/Slash Parameters
| Parameter | Symbol | Suggested Range | Purpose |
|-----------|--------|-----------------|----------|
| Stake | E | 10,000-100,000 | Collateral |
| Reward | R | 0.1% E/month | Liveness incentive |
| Slash | S | 1-10% E | Violation penalty |
| Dispute window | D | 24-72 hours | Challenge period |
| Δt_max | Δt | 5-30s | Liveness bound |
| R_max | R_MAX | 10^9 gas | Resource cap |

### Reward Funding
```
Reward distribution sources (algorithmically controlled):
  1. Protocol fees (% of each action execution fee)
  2. Buy-and-burn recovery (portion of fee router allocation)
  3. Fee discount vouchers (earned through liveness performance)

Distribution: Proportional to liveness score L(T)
Note: Rewards are for service provision, not investment returns.
```

### Utility Function
```
U(σ,T) = R·L(T) - S·V(T) - C·W(T)

Where:
  L(T) = liveness score (uptime × throughput)
  V(T) = verified violations (from O4 audit)
  W(T) = work performed (base cost)
```

### Incentive Compatibility
```
For S > max Gain(σ_deviant), compliance is dominant:

  E[U(compliant)] > E[U(deviant)]

Detection: Pr[detect|deviate] → 1 via O4 audit completeness
Slash: Executes automatically after dispute window D
```

### Slashing Workflow with Dispute
```
1. AUDIT_LOG records all actions
2. Verifier detects violation → submits slash proposal
3. DISPUTE WINDOW (D hours): Operator can submit counter-evidence
4. If no valid dispute → governance confirms → slash executes
5. Slashed funds → 90% treasury, 10% whistleblower
6. False accusation → accuser loses bond
```

### Integration with Validators/AVS
```
Operator Set Selection:
  - Stake registration on-chain (Tau governance)
  - Minimum stake threshold for eligibility
  - Reputation score from historical L(T)

Consensus Integration:
  - Operators run as AVS (Actively Validated Service)
  - Shared security with underlying L1/L2
  - Slashing conditions enforced by consensus
```

---

## 7. Lean 4 Verification

```lean
/-- Core composition theorem: data + control plane safety -/
theorem combined_safety :
  ∀ (p : P) (s : S) (a : A) (op : Op),
    ExecCalled p s a ∧ OpExecCalled p s op →
    Allowed p s a ∧ Allowed_op p s op := by
  intro p s a op ⟨h_data, h_control⟩
  constructor
  · exact safety_invariant p s a h_data          -- From MPRD core
  · exact O1_operator_bounded p s op h_control   -- From O1 axiom

/-- Liveness lemma: with active compliant operator -/
theorem liveness_under_compliance :
  ∀ (p : P) (s : S) (op : Operator),
    Compliant(op) ∧ Active(op) ∧ (∃a. Allowed p s a) →
    Eventually (λt => ExecCalled p s (some_allowed_action t))
```

**Proof status**: O1, O3, O4, O7 formalized. Composition theorem verified. Liveness lemma requires temporal logic extension.

---

## 8. Summary

| Invariant | Enforces | Code Hook |
|-----------|----------|-----------|
| O1 | Policy-bound ops | `policy.allows()` |
| O2 | Bounded liveness | Watchdog + failover |
| O3 | Policy immutability | Read-only policy ref |
| O4 | Complete audit | `append_immutable()` |
| O5 | Token expiry | `expires_at` check |
| O6 | Economic alignment | Stake/slash contract |
| O7 | Anti-replay | Nonce registry |
| O8 | Resource caps | `R_MAX` bound |
| O9 | Threshold auth | k-of-n signatures |

---

**Links**: [Tau Net](https://tau.net) | [Lean Proofs](./MPRD_Operator.lean) | [Academic Paper](./MPRD_Operator_Ledger.pdf)

*MPRD Operator v1.1 — Formal liveness guarantees for autonomous infrastructure*
