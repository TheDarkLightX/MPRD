# Tau Tables + Henkin (DQBF-style) Quantification — Notes for MPRD

This note captures how “quantification over Boolean functions” appears in Tau’s **Tables** abstraction and how to reason about it with MPRD’s evidence-first workflow.

Primary reference: Ohad Asor, *Theories and Applications of Boolean Algebras* (draft v0.25, 2024-08-10) ([PDF](file:///home/trevormoc/Downloads/MPRD/external/tau-lang/docs/Theories-and-Applications-of-Boolean-Algebras-0.25.pdf)).

## 1) What “Tables” are (as logic)

In TABA §8.2, a table is a function \(T:2^n \to B\) where \(B\) is a Boolean algebra supported in Tau (including product algebras).
Operationally: it’s a total map from n-bit keys to values (default is 0), i.e. a **Boolean function returning BA elements**.

Tau introduces syntactic sugar for common table operations:
- `set(T,k,v)` : functional update at key `k`
- `select(T, φ(v))` : filter by predicate on values
- `common(T2,T3)` : intersection-style operation “as sets of tuples”

Critically, these are conservative extensions: each can be expanded into first-order constraints over the underlying BF representation (TABA §8.2).

## 2) Henkin quantifiers = “controlled dependency” synthesis

Henkin/branching quantifiers look like:
- `∀x1 x2 ∃y1(x1) y2(x2) . φ`

This is **not** ordinary QBF: it’s DQBF-flavored dependency control (each existential depends only on a subset of universals).

In practice, “A: decide satisfiable/unsat” means:
- does there exist a set of Skolem functions (with the given dependency restrictions) that make the formula true?

## 3) Key TABA insight: Boolean Skolem functions suffice

TABA §4.10 (“Skolem and Henkin”) proves a powerful elimination statement (Theorem 4.8):

For Boolean \(f(x,y)\), \(f(x,y)=0\) is solvable iff \(y\) can be written as a Boolean function of \(x\):
\[
y(x) = y_1 x + y_0 x'
\]
with constraints:
\[
f(0,y_0)=0 \wedge f(1,y_1)=0
\]

The multivariate generalization is minterm normal form:
\[
y(X) = \sum_A y_A X^A,\;\;\; f(A,y_A)=0 \text{ for all } A.
\]

Interpretation for MPRD:
- Existential function quantification can be reduced to existential quantification over **a finite family of BA elements** \(\{y_A\}\) (table entries / coefficients).

## 4) Why the problem is hard (but where it becomes tractable)

General DQBF decision is very hard (NEXPTIME-complete is the usual reference class), because:
- quantifying over a function means choosing a truth table (size \(2^{|deps|}\)) or a circuit.

However, **Tau Tables** give you a structured representation that can be tractable when:
- the key width `n` is small (exact elimination by enumerating/encoding all \(y_A\)),
- or the table can be represented compactly (BDD/ROBDD / algebraic normal forms),
- or you restrict the fragment (e.g., certain “table update” patterns that are compositional).

## 5) MPRD “Morph kernel” workflow for this domain

Evidence-first workflow (Popper loop):
- **Falsifier mining**: propose a dependency restriction / optimization rule (“this transformation preserves satisfiability”) and try to break it with a minimal counterexample.
- **Promotion** only if backed by replayable artifacts:
  - a witness Skolem table (SAT) or a counterexample assignment (UNSAT/violation),
  - deterministic re-check.

Practical: use a bounded brute-force checker for very small instances (k ≤ 6, deps ≤ 4), then scale via CEGIS/solver encodings.

## 6) Immediate tooling added

See `tools/logic/dqbf_bruteforce.py` for a deterministic, bounded brute-force solver for a small DQBF/Henkin fragment.
It is designed as a falsifier oracle for proposed “table rewrite” laws and dependency restrictions.

## 7) Blockchain-motivated toy shapes (what to learn)

These are tiny but capture the core semantics:

### (A) `set` as a conservative extension (always satisfiable)
Model:
- `idx` is universal (the table lookup key).
- `k` and `v` are existential constants (the update key/value).
- `T0(idx)` and `T1(idx)` are existential tables.
- Constraint: for all `idx`, `T1(idx) = if idx==k then v else T0(idx)`.

Example file: `tools/logic/examples/table_set_conservative.json`.

### (B) Spending from a 1-bit ledger table under universal prior state
Model:
- Universals: `idx`, and a 2-entry prior-state table encoded as bits `Bal0`, `Bal1`.
  We define `Bal(idx) = (¬idx ∧ Bal0) ∨ (idx ∧ Bal1)`.
- Existentials:
  - choose spend key `k(Bal0,Bal1)` (Henkin dependency: depends on state, not on idx),
  - output updated table `BalAfter(idx,Bal0,Bal1)`.
- Update semantics: `BalAfter(k)=0` and other entries unchanged.

Two variants:
- `ledger_spend_forall_states_unsat.json`: requires picking `k` such that `Bal(k)=1` for **all** states (UNSAT).
- `ledger_spend_with_guard_sat.json`: guarded: only requires spending when `(Bal0 ∨ Bal1)` is true (SAT).

These teach the key lesson: Henkin dependencies let you express “pick a witness key based on state,” and satisfiability hinges on whether the property must hold in *all* states or only under a guard.

### (C) Add a “commitment bit” (toy root) to bind tables to an on-chain claim
Even in a 1-bit-key table, you can model a commitment relationship:
- Universals include a claimed root bit `R`.
- Constrain `R = Bal0 XOR Bal1`.

This binds the table’s contents to an external “commitment” value (toy Merkle root).
Then you can add guarded spend semantics under Henkin witness `k(Bal0,Bal1)`.

Example file: `tools/logic/examples/ledger_spend_with_commitments_sat.json`.

Scaling note: once you make the “root” a real hash of a larger table, brute-force truth-table enumeration explodes and you must switch to a compact representation (BDD/circuit) + CEGIS/solver checks.

### (D) 2-bit key table without blow-up: “unique UTXO” toy
To get a **2-bit key** (4-entry table) while staying brute-force friendly, restrict the state shape:
- Universal bits: `E` (empty), `p0,p1` (position of the unique 1).
- Semantics: if `E=1` table is all-zero; else exactly one cell is 1 at index `p`.

Then the Henkin witness is straightforward:
- spend key `k(p) = p` (depends only on `p0,p1`)
- post-commitment `RootAfter = 0`

This demonstrates the full “pick key based on state” Henkin pattern without exploding.
Example file: `tools/logic/examples/ledger_2bit_unique_utxo_sat.json`.

