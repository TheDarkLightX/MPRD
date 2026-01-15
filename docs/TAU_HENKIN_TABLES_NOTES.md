# Tau Tables + Henkin (DQBF-style) Quantification — Notes for MPRD

This note captures how “quantification over Boolean functions” appears in Tau’s **Tables** abstraction and how to reason about it with MPRD’s evidence-first workflow.

Primary reference: Ohad Asor, *Theories and Applications of Boolean Algebras* (draft v0.25, 2024-08-10) ([PDF](file:///home/trevormoc/Downloads/MPRD/external/tau-lang/docs/Theories-and-Applications-of-Boolean-Algebras-0.25.pdf)).

## Scope / epistemic status (important)

This document contains two kinds of claims:

- **Proved (Lean) + falsified (Morph), but for a simplified model**: we formalize *toy* table semantics as total functions \(T:K\to V\) with functional update `set` and pointwise operators like `mapTable`. Those theorems are 100% rigorous **for that model**.
- **Tau-language applicability**: whether these laws apply *as-is* to Tau depends on whether Tau’s actual `Table`/`set`/`select` semantics match the model. **We do not yet have a refinement proof** connecting Tau’s semantics/implementation to the Lean model, so treat “applies to Tau” as *unproven* until such a proof exists.

What we can safely take today: these results clarify the **structure** of “table-like” operators in Boolean-algebraic settings (what scales if an operator is pointwise, what breaks if it is global).

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

## 8) Popper-mined table rewrite insight: `select ∘ set`

For a 1-bit key table with a 2-bit value `(hi,lo)`, consider:
- `select(T)` keeps rows where `hi==1`, returning `(hi, hi∧lo)` (so low bit is zeroed unless hi is set).
- `set(T,k,v)` overwrites key `k` with value `v`.

Naive rewrite (UNSOUND):
`select(set(T,k,v))  ==  set(select(T),k,v)`

Counterexample exists when `v.hi=0` and `v.lo=1`: the LHS selection will zero-out `lo`, but the RHS inserts `lo` unchanged.
We encoded this as a satisfiable “mismatch exists” instance:
- `tools/logic/examples/table_select_set_naive_unsound_sat.json`

Refined rewrite (SOUND in this bounded model):
`select(set(T,k,v))  ==  set(select(T),k, select_val(v))`
where `select_val(v) = (v.hi, v.hi ∧ v.lo)`.

We encoded “mismatch exists” and it is UNSAT:
- `tools/logic/examples/table_select_set_refined_sound_unsat.json`

### Logic formulas (what we actually proved / falsified)

Let a table be a total function \(T : K \to V\).

- **Set (overwrite)**:

\[
\mathrm{set}(T,k,v)(i) \;\triangleq\; \begin{cases}
v & i = k\\
T(i) & i \neq k
\end{cases}
\]

- **Select (filter + canonicalize)**, for a predicate \(P:V\to\mathsf{Bool}\), a canonicalizer \(C:V\to V\), and a distinguished zero \(0\in V\):

\[
\mathrm{select}(T)(i) \;\triangleq\; \begin{cases}
C(T(i)) & P(T(i))\\
0 & \neg P(T(i))
\end{cases}
\]

In our 2-bit demo: \(K=\{0,1\}\), \(V=\{0,1\}^2\) with \(v=(hi,lo)\), \(P(v)\equiv (hi=1)\),
\(C(v)=(hi, hi\wedge lo)\), and \(0=(0,0)\).

- **Naive rewrite (UNSOUND)**:

\[
\mathrm{select}(\mathrm{set}(T,k,v)) \stackrel{?}{=} \mathrm{set}(\mathrm{select}(T),k,v)
\]

This is falsified by the (Morph-mined) witness \(T\equiv 0\), \(k=0\), \(v=(0,1)\), \(i=0\).
See the Morph evidence bundle:
- `tools/logic/morph_evidence/table_select_set_naive/bundle/packet.json`

- **Refined rewrite (SOUND)**:

\[
\mathrm{select}(\mathrm{set}(T,k,v)) \;=\; \mathrm{set}(\mathrm{select}(T),k,\mathrm{selectVal}(v))
\]

This is proved in Lean (for all tables \(T: \mathsf{Bool}\to ( \mathsf{Bool}\times\mathsf{Bool})\)):
- `LeanProofs/TauTables_SelectSet.lean` (`select_set_refined`)

and the naive counterexample is also proved:
- `LeanProofs/TauTables_SelectSet.lean` (`select_set_naive_counterexample`)

### Why this “scales”

The key point is that the refined law is a **parametric** identity: it is pointwise in the table index \(i\),
and it only requires that the inserted value be transformed by the *same* selection/canonicalization rule.
In practice, this is how you safely push selection past update without quantifying an entire post-state table.

## 9) Next law: `select` is idempotent (and the exact precondition)

Once you represent `select` as a pointwise value-transformer \(g:V\to V\) (filter+canonicalize into a distinguished zero),
the table-level idempotence law:

\[
\mathrm{select}(\mathrm{select}(T)) = \mathrm{select}(T)
\]

reduces to the *value-level* precondition:

\[
\forall v,\; g(g(v)) = g(v).
\]

We proved this for the concrete 2-bit demo `selectVal(hi,lo)=(hi,hi∧lo)`:
- Lean: `LeanProofs/TauTables_SelectSet.lean` (`selectVal_idempotent`, `select_idempotent`)

And we used Morph to mine a precise falsifier when you violate this precondition (swap in a non-idempotent canonicalizer `selectVal_bad(hi,lo)=(hi,¬lo)`):
- Morph evidence (strict, SOLVED): `tools/logic/morph_evidence/table_select_idempotence_bad/bundle/packet.json`

This is a reusable pattern for “scaled rewrites”: prove the parametric law in Lean, and keep a Morph falsifier domain that pins what assumption is necessary by producing counterexamples when it is violated.

## 10) A “pointwise table algebra” (what rewrites scale, and what does not)

The safe fragment is: **table operators that are pointwise maps**.

Define \(f^\*(T)(i)\triangleq f(T(i))\). In Lean this is `mapTable f T`.

### Core laws (all key sizes \(K\), no enumeration)

- **Map distributes over set (the pushthrough law)**:

\[
f^\*(\mathrm{set}(T,k,v))=\mathrm{set}(f^\*(T),k,f(v)).
\]

Lean: `LeanProofs/TauTables_SelectSet.lean` (`map_setTable`).

- **Idempotence lifts pointwise**:

If \(\forall v,\; f(f(v))=f(v)\) then \(\forall T,\; f^\*(f^\*(T))=f^\*(T)\).

Lean: `LeanProofs/TauTables_SelectSet.lean` (`map_idempotent`).

### Why our `select` rewrites are *exactly* these laws

In the 2-bit demo, the predicate check in `select` is redundant because:

\[
\mathrm{selectVal}(hi,lo)=(hi,hi\wedge lo)
\]

already maps non-selected values (\(hi=0\)) to the distinguished zero \((0,0)\). Formally:

\[
\big(\, \text{if } hi(v)\text{ then }\mathrm{selectVal}(v)\text{ else }0 \,\big)=\mathrm{selectVal}(v).
\]

Lean: `LeanProofs/TauTables_SelectSet.lean` (`selectVal_eq_if`, `select_eq_mapTable_selectVal`).

Therefore:
- `select ∘ set` refined rewrite is a direct corollary of `map_setTable`.
- `select` idempotence is a direct corollary of `map_idempotent` + `selectVal_idempotent`.

### What does *not* scale: non-pointwise operators

Anything that depends on **multiple cells at once** (e.g., a Merkle root/hash of the whole table, a global sum, “exists key with property”) is *not* a pointwise `mapTable`.
For such operators, pushing `set` past the operator generally requires *extra information* (e.g., the old value at `k`, or an auxiliary proof/certificate), and naive rewrites will be falsifiable.

## 11) Non-pointwise example: “root XOR” shows why you need the old cell (or a certificate)

To make the failure mode concrete, define a *global* summary for Bool-key Bool-valued tables:

\[
\mathrm{rootXor}(T)\triangleq T(0)\oplus T(1)
\]

This operator depends on **multiple cells**, so it is not representable as `mapTable f`.

### Naive rewrite (UNSOUND)

\[
\mathrm{rootXor}(\mathrm{set}(T,k,v)) \stackrel{?}{=} \mathrm{rootXor}(T)\oplus v
\]

Morph mined a strict counterexample witness (replayable evidence bundle):
- `tools/logic/morph_evidence/table_root_xor_naive/bundle/packet.json`

### Correct rewrite (needs the old cell)

For XOR, the correct update is:

\[
\mathrm{rootXor}(\mathrm{set}(T,k,v)) = \mathrm{rootXor}(T)\oplus T(k)\oplus v
\]

Lean proof (for the Bool-key Bool-valued toy model):
- `LeanProofs/TauTables_SelectSet.lean` (`rootXor_set`)

This is the general pattern for “global” operators: to push `set` through them, you either need
the old cell value `T(k)` or an auxiliary certificate that lets you recover it.

### What would count as “strong proof this applies to Tau”

To claim a rewrite law like `select ∘ set` is valid for Tau (not just for our Lean toy model), we would need evidence at the following level:

- **Formal semantic bridge**: a Lean definition of Tau `Table` and its operations (from the Tau/TABA specification), plus a theorem that Tau’s `set`/`select` are extensionally equal to the functions we assume (`setTable`, `mapTable`/value-transformer form).
- **Implementation refinement (optional but ideal)**: connect Tau’s evaluator/compiler behavior to the semantic bridge (e.g., show evaluation produces the same function as the semantic model).
- **Side-condition audit**: confirm the same zero element, equality notion, and any non-Boolean-algebra effects (partiality, “unknown”, effects, evaluation order) are either absent or accounted for.

Until then, the Lean proofs should be read as “this law is correct for the abstract table-as-function model”, and the Morph bundles should be read as “this is exactly how naive laws fail when the needed precondition is missing”.