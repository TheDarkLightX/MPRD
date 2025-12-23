use crate::Hash256;
use sha2::{Digest, Sha256};

/// Domain separation for Fiat-Shamir challenge seed derivation (must match prover/verifier).
const CHALLENGE_DOMAIN_V1: &[u8] = b"MPRD_MPB_PROOF_CHALLENGE_V1";

/// Domain separation for deriving deterministic spot check indices (must match prover/verifier).
const SPOT_CHECK_DOMAIN_V1: &[u8] = b"MPRD_MPB_PROOF_SPOT_CHECKS_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpotCheckDerivationError;

pub(crate) fn challenge_seed_v1(
    bytecode_hash: &Hash256,
    input_hash: &Hash256,
    context_hash: &Hash256,
    trace_root: &Hash256,
    output: i64,
    num_steps: usize,
    fuel_consumed: u32,
) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_DOMAIN_V1);
    hasher.update(bytecode_hash);
    hasher.update(input_hash);
    hasher.update(context_hash);
    hasher.update(trace_root);
    hasher.update(output.to_le_bytes());
    hasher.update((num_steps as u64).to_le_bytes());
    hasher.update(fuel_consumed.to_le_bytes());
    hasher.finalize().into()
}

pub(crate) fn derive_spot_check_indices_v1(
    seed: &Hash256,
    num_steps: usize,
    num_checks: usize,
) -> Result<Vec<usize>, SpotCheckDerivationError> {
    if num_steps <= 2 || num_checks == 0 {
        return Ok(vec![]);
    }

    let available = num_steps - 2;
    let want = num_checks.min(available);
    if want == 0 {
        return Ok(vec![]);
    }

    use std::collections::BTreeSet;

    let mut chosen: BTreeSet<usize> = BTreeSet::new();
    let mut counter: u64 = 0;
    let max_rounds: u64 = 10_000;

    while chosen.len() < want {
        if counter >= max_rounds {
            return Err(SpotCheckDerivationError);
        }

        let mut hasher = Sha256::new();
        hasher.update(SPOT_CHECK_DOMAIN_V1);
        hasher.update(seed);
        hasher.update(counter.to_le_bytes());
        let digest: [u8; 32] = hasher.finalize().into();

        for chunk in digest.chunks_exact(8) {
            if chosen.len() >= want {
                break;
            }
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(chunk);
            let r = u64::from_le_bytes(tmp);
            let idx = (r % (available as u64)) as usize + 1;
            chosen.insert(idx);
        }

        counter += 1;
    }

    Ok(chosen.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn any_hash256() -> impl Strategy<Value = Hash256> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        #[test]
        fn seed_is_deterministic_for_same_inputs(
            bytecode_hash in any_hash256(),
            input_hash in any_hash256(),
            context_hash in any_hash256(),
            trace_root in any_hash256(),
            output in any::<i64>(),
            num_steps in 0usize..10_000,
            fuel in any::<u32>(),
        ) {
            let a = challenge_seed_v1(
                &bytecode_hash,
                &input_hash,
                &context_hash,
                &trace_root,
                output,
                num_steps,
                fuel,
            );
            let b = challenge_seed_v1(
                &bytecode_hash,
                &input_hash,
                &context_hash,
                &trace_root,
                output,
                num_steps,
                fuel,
            );
            prop_assert_eq!(a, b);
        }

        #[test]
        fn derived_indices_are_unique_sorted_and_in_range(
            seed in any_hash256(),
            num_steps in 0usize..512,
            num_checks in 0usize..128,
        ) {
            let idx = derive_spot_check_indices_v1(&seed, num_steps, num_checks).expect("derive");
            if num_steps <= 2 || num_checks == 0 {
                prop_assert!(idx.is_empty());
                return Ok(());
            }

            let available = num_steps - 2;
            let want = num_checks.min(available);
            prop_assert_eq!(idx.len(), want);

            // Sorted + unique.
            let mut sorted = idx.clone();
            sorted.sort();
            sorted.dedup();
            prop_assert_eq!(sorted, idx.clone());

            // Bounds: always exclude first and last steps.
            for i in &idx {
                prop_assert!(*i >= 1);
                prop_assert!(*i + 1 < num_steps);
            }
        }
    }
}
