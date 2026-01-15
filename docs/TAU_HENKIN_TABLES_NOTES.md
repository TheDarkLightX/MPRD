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

