# Testing (Unit, Property, Fuzz, and “Fail-Closed” Safety)

This repo treats “safe to change” as a primary objective. Tests are written to:

- validate **observable behavior** (not internal steps),
- prevent catastrophic failures on critical paths,
- keep correctness checks **deterministic**, **fast**, and **high-signal**.

Related docs:
- `docs/FUZZING.md` (coverage-guided fuzzing + stateful PBT pointers)
- `docs/SECURITY_FUZZING.md` (internal fuzzing workflow)

## Unit tests (Rust): practical rules

1) Test behavior, not implementation  
Assert outputs/state changes/events. If refactors break tests without behavior changes, tests are too coupled.

2) Keep tests deterministic + isolated  
No real network/filesystem/clock/randomness/env. Inject dependencies via traits (e.g., `Clock`, `Rng`, `Store`).

3) One reason to fail per test  
Split tests or use table-driven cases so failures are obvious.

4) Arrange–Act–Assert  
Make the “what” unmistakable.

5) Stable error assertions  
Prefer `matches!(...)`, error enums, and typed error kinds over string matching.

6) Mock boundaries, not internals  
Mock DB/HTTP clients at the edge; avoid deep call-chain mocks (create a seam instead).

7) Edge cases, systematically  
Empty/missing, min/max, off-by-one, invalid formats, duplicates, ordering, and “large but fast” inputs.

8) Keep tests fast  
Unit tests should be milliseconds. Put slow/IO-heavy checks in integration tests (`tests/`) or longer-running jobs.

9) Coverage is a map, not a goal  
Use coverage to find blind spots. Use mutation testing when you suspect assertions are too weak.

## Property-based tests (proptest): high-signal patterns

Property tests are most valuable when you can express an invariant or compare against an independent model.

### Strong property shapes
- **Round-trip**: `decode(encode(x)) == x`
- **Idempotence**: `normalize(normalize(x)) == normalize(x)`
- **Metamorphic**: transforming input in a known way transforms output predictably
- **Refinement**: optimized implementation == simple reference model
- **Conservation**: totals preserved, balances never negative, invariants hold

### Generator rules of thumb
- Prefer **valid-by-construction** strategies over `prop_assume!` filtering.
- Force edge cases with `prop_oneof!` (empty/0/1/MAX/duplicates/very long inputs).
- Optimize shrinking: generate from naturally-shrinking structures, or map from a simpler representation.

### Stateful systems: use model-based/state-machine testing
Generate sequences of operations, maintain a simple model state, and check equivalence after every step.

### Reproducibility
When a `proptest` fails, keep the minimized counterexample or the seed as a permanent regression.
This repo uses `proptest-regressions/` files (when generated) as regression artifacts; keep them in version control unless intentionally replaced with an explicit unit regression.

Useful env vars:
- `PROPTEST_CASES=256` (increase exploration)
- `PROPTEST_SEED=...` (reproduce a failing run)
- `PROPTEST_VERBOSE=1` (debugging)

## Mutation testing (optional, high ROI)

Mutation testing answers: “Would tests fail if the code were subtly wrong?”
Use it when:
- coverage is high but bugs still slip through,
- tests feel too “happy-path”,
- properties exist but don’t actually constrain behavior.

Suggested tool (external): `cargo-mutants` (run locally; not required for normal development).

## Miri + sanitizers (optional)

For `unsafe` code or very tricky logic, these runs catch classes of bugs unit tests miss.

Miri:
- `rustup +nightly component add miri`
- `cargo +nightly miri test -p <crate>`

Sanitizers (nightly):
- `RUSTFLAGS=\"-Zsanitizer=address\" cargo +nightly test -p <crate>`

## Quick commands

- Fast local loop: `tools/test.sh fast`
- Deeper exploration: `PROPTEST_CASES=512 tools/test.sh pbt-core`
