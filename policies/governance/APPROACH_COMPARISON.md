# Tau Governance Spec Approaches - Comparison

## Canonical Specs (Production-Ready)

See `canonical/` directory for the recommended specs:

| Canonical Spec | Based On | Status |
|----------------|----------|--------|
| **mprd_governance_gate.tau** | Approach 2 | ⭐ RECOMMENDED |
| **mprd_committee_quorum.tau** | Approach 5 | ✅ Production |
| **mprd_timelock.tau** | Approach 4 | ✅ Production |
| **mprd_escalation.tau** | Approach 8 | ✅ Production |
| **mprd_conviction.tau** | Approach 11b | ✅ Production |

## Experimental Results (12 Approaches Tested)

| Approach | Works? | Complexity | Use Case |
|----------|--------|------------|----------|
| 1. sbf-only | ✅ Yes | Low | Simple gates, exhaustive testing |
| 2. bv[8] + ternary | ✅ Yes | Medium | **Enum-based routing** ⭐ |
| 3. Temporal FSM | ✅ Yes | High | Multi-step workflows |
| 4. Timelock (sbf) | ✅ Yes | Medium | Delay-based governance |
| 5. Quorum (sbf) | ✅ Yes | Low | Committee voting |
| 6. Weighted voting | ✅ Yes | Medium | Stake-weighted decisions |
| 7. Nonce replay protection | ✅ Yes | Medium | Multi-sig security |
| 8. Escalation ladder | ✅ Yes | Medium | Tiered authorization |
| 9. DPoS (sbf) | ✅ Yes | Low | Delegated stake voting |
| 9b. DPoS (bv[16]) | ❌ Freezes | High | - |
| 10. Liquid democracy | ❌ Freezes | High | Transitive delegation |
| 11. Conviction (sbf) | ✅ Yes | Medium | Time-weighted voting |
| 11b. Conviction (bv) | ❌ Freezes | High | - |
| 12. Quadratic (sbf) | ✅ Yes | Medium | Cost-based voting |
| 12b. Quadratic (bv) | ❌ Freezes | High | - |

## Key Learnings

### What Works in Tau Execution Mode

1. **Pure sbf (Boolean) logic** - Always works reliably
2. **bv[N] equality checks with ternary** - `(x = {#x01}:bv[8]) ? then : else`
3. **Temporal recurrence relations** - `o[t] = f(o[t-1], i[t])`
4. **Initial conditions** - `o[0] = value`
5. **File-based I/O** - Deterministic and testable

### What Doesn't Work

1. **sbf & bv[N] mixing in conditionals** - Type conflict error
   ```tau
   # ERROR: Conflicting type information
   (o_bv[t] = (i_sbf[t] & {1}:bv[8]) | (i_sbf[t]' & {0}:bv[8]))
   ```

2. **Complex bv[16] arithmetic** - Causes interpreter freeze
   ```tau
   # FREEZES: Multiple bv additions with conditionals
   (o_total[t] = o_eff_v0[t] + o_eff_v1[t] + o_eff_v2[t])
   ```

3. **Same-step output dependencies** - Causes freeze or unsat
   ```tau
   # FREEZES: o_eff_b depends on o_eff_c in same step
   (o_eff_c[t] = i_vote_c[t]) &&
   (o_eff_b[t] = ... o_eff_c[t] ...)
   ```

4. **Circular dependencies in same step** - Causes "unsat"
   ```tau
   # ERROR: Circular
   (o_a[t] = ... o_b[t] ...) && (o_b[t] = ... o_a[t] ...)
   ```

### Design Principle: Host Computes, Tau Validates

For complex governance (DPoS, liquid democracy, quadratic voting):
- **Host** computes stake weights, delegation resolution, vote costs
- **Tau** validates the pre-computed authorization flags (sbf-only)
- This avoids bv arithmetic in Tau while keeping logic verifiable

## Recommended Patterns

### Pattern 1: Boolean Gate (Simplest)
```tau
(o_accept[t] = (cond1 & cond2) | (cond3 & cond4))
```

### Pattern 2: bv[8] Enum Decode
```tau
((i_kind[t] = {#x01}:bv[8]) ? (o_is_type_a[t] = 1) : (o_is_type_a[t] = 0)) &&
(o_result[t] = o_is_type_a[t] & other_cond)
```

### Pattern 3: Temporal Delay Chain
```tau
(o_pending[0] = 0) &&
(o_pending[t] = trigger | (o_pending[t-1] & keep_condition)) &&
(o_waited_1[t] = o_pending[t-1]) &&
(o_waited_2[t] = o_waited_1[t-1]) &&
(o_ready[t] = o_waited_2[t])
```

### Pattern 4: Sticky Latch
```tau
(o_passed[0] = 0) &&
(o_passed[t] = o_passed[t-1] | trigger)
```

### Pattern 5: M-of-N Quorum (sbf-only)
```tau
(o_quorum[t] = (v0 & v1) | (v0 & v2) | (v1 & v2))
```

## File Structure
```
policies/governance/
├── approach1_sbf_only.tau         # Pure Boolean, 6 inputs
├── approach2_bv8_ternary.tau      # bv[8] update_kind decode
├── approach3_temporal_fsm.tau     # Console-based FSM
├── approach4_timelock_v2.tau      # sbf delay chain
├── approach5_quorum_sbf.tau       # 2-of-3 Boolean voting
├── inputs/                        # Test input files
├── outputs/                       # Test output files
└── APPROACH_COMPARISON.md         # This file
```

## Recommendations

### For MPRD Governance Gate
**Use Approach 2** (bv[8] with ternary decode):
- Clean interface (single update_kind input)
- Maps directly to Rust `UpdateKind` enum
- Extensible to more update types
- Works reliably with file I/O

### For Committee Voting
**Use Approach 5** (sbf-only quorum):
- Simple combinatorial logic
- No bv arithmetic issues
- Easy to extend to larger committees
- Sticky latch captures "passed" state

### For Timelocked Operations
**Use Approach 4** (sbf delay chain):
- Avoids bv arithmetic type conflicts
- Clear state progression
- Configurable delay via chain length
