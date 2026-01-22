/-!
## Tau Tables: `select ∘ set` rewrite (Lean proof artifact)

This file proves a concrete instance of a table rewrite law that we Popper-mined with bounded
counterexamples in `tools/logic/examples/`:

Naive (UNSOUND):
  select(set(T,k,v)) = set(select(T),k,v)

Refined (SOUND):
  select(set(T,k,v)) = set(select(T),k, selectVal(v))

Model:
- Key type: Bool (1-bit key table).
- Value type: Bool × Bool (2-bit payload, interpreted as (hi, lo)).
- select predicate: keep rows with hi=true, and canonicalize payload as (hi, hi && lo).
-/

namespace Mprd.Tau.Tables

abbrev Val : Type := Bool × Bool
abbrev Table : Type := Bool → Val

def hi (v : Val) : Bool := v.1
def lo (v : Val) : Bool := v.2

def zeroVal : Val := (false, false)

def selectVal (v : Val) : Val :=
  (hi v, hi v && lo v)

def select (T : Table) : Table :=
  fun i =>
    let v := T i
    if hi v then selectVal v else zeroVal

def set (T : Table) (k : Bool) (v : Val) : Table :=
  fun i => if i = k then v else T i

/-!
### Scaling lemma (parametric, key-size independent)

The refined `select ∘ set` law is a special case of the general "map commutes with set"
fact: for any key type `K` with decidable equality, any table `T : K → V`, and any
pointwise transformer `f : V → W`, we have:

  mapTable f (setTable T k v) = setTable (mapTable f T) k (f v)

Operationally: pushing a pointwise operation through an update is always sound, and the
refined rule is exactly the instance where `f` is the selection/canonicalization function.
-/

universe u v w

def setTable {K : Type u} [DecidableEq K] {V : Type v} (T : K → V) (k : K) (val : V) : K → V :=
  fun i => if i = k then val else T i

def mapTable {K : Type u} {V : Type v} {W : Type w} (f : V → W) (T : K → V) : K → W :=
  fun i => f (T i)

theorem map_setTable {K : Type u} [DecidableEq K] {V : Type v} {W : Type w}
    (f : V → W) (T : K → V) (k : K) (val : V) :
    mapTable f (setTable T k val) = setTable (mapTable f T) k (f val) := by
  funext i
  by_cases h : i = k
  · simp [mapTable, setTable, h]
  · simp [mapTable, setTable, h]

theorem map_idempotent {K : Type u} {V : Type v} (f : V → V) (T : K → V)
    (hf : ∀ x, f (f x) = f x) :
    mapTable f (mapTable f T) = mapTable f T := by
  funext i
  simp [mapTable, hf]

theorem selectVal_idempotent (v : Val) :
    selectVal (selectVal v) = selectVal v := by
  cases v with
  | mk a b =>
      cases a <;> cases b <;> simp [selectVal, hi, lo]

theorem selectVal_eq_if (v : Val) :
    (if hi v then selectVal v else zeroVal) = selectVal v := by
  cases v with
  | mk a b =>
      cases a <;> cases b <;> simp [selectVal, hi, lo, zeroVal]

theorem select_eq_mapTable_selectVal (T : Table) :
    select T = mapTable selectVal T := by
  funext i
  simp [select, mapTable, selectVal_eq_if]

/-!
### Generalization: when `select` is pointwise (and scales)

Given a predicate `P` and canonicalizer `C`, define a "selection transformer"
`g(v) = if P v then C v else zero`.

If `C` already maps all non-selected values to `zero`, then `g = C` and the table-level select
is literally a pointwise map `mapTable C`.
-/

def selectOp {V : Type v} (P : V → Bool) (C : V → V) (zero : V) (x : V) : V :=
  if P x then C x else zero

theorem selectOp_eq_C_of_C_maps_nonP_to_zero {V : Type v} (P : V → Bool) (C : V → V) (zero : V)
    (hC : ∀ x, P x = false → C x = zero) :
    ∀ x, selectOp (V := V) P C zero x = C x := by
  intro x
  cases hx : P x with
  | false =>
      have hz : C x = zero := hC x hx
      -- selectOp chooses `zero` when P x = false; rewrite with hz.
      simp [selectOp, hx, hz]
  | true =>
      simp [selectOp, hx]

theorem select_idempotent (T : Table) :
    select (select T) = select T := by
  -- Derive from `map_idempotent` using `select = mapTable selectVal`.
  simpa [select_eq_mapTable_selectVal] using
    (map_idempotent (K := Bool) (V := Val) (f := selectVal) (T := T) (hf := fun x => selectVal_idempotent x))

theorem select_set_refined (T : Table) (k : Bool) (v : Val) :
    select (set T k v) = set (select T) k (selectVal v) := by
  -- Derive directly from `map_setTable` using `select = mapTable selectVal`.
  simpa [select_eq_mapTable_selectVal, setTable, set, mapTable] using
    (map_setTable (K := Bool) (V := Val) (W := Val) (f := selectVal) (T := T) (k := k) (val := v))

/-!
### A non-pointwise example (global operator): XOR-root update needs the old cell

If you define a global table summary like `root(T) = XOR over all keys`, then pushing `set`
through it is not pointwise: the correct update needs the old value at the updated key.

We prove, for Bool-key tables with Bool values:
  rootXor(set(T,k,v)) = rootXor(T) XOR T(k) XOR v

and we show a naive rewrite that omits `T(k)` is false.
-/

def rootXor (T : Bool → Bool) : Bool :=
  xor (T false) (T true)

theorem rootXor_set (T : Bool → Bool) (k : Bool) (v : Bool) :
    rootXor (setTable (K := Bool) (V := Bool) T k v) = xor (xor (rootXor T) (T k)) v := by
  -- Prove by finite case split on k and the two table entries.
  cases k <;> cases h0 : T false <;> cases h1 : T true <;> cases v <;>
    simp [rootXor, setTable, h0, h1]

theorem rootXor_set_naive_counterexample :
    ∃ (T : Bool → Bool) (k : Bool) (v : Bool),
      rootXor (setTable (K := Bool) (V := Bool) T k v) ≠ xor (rootXor T) v := by
  let T : Bool → Bool := fun i => if i = false then true else false
  let k : Bool := false
  let v : Bool := true
  refine ⟨T, k, v, ?_⟩
  -- Evaluate both sides.
  simp [T, k, v, rootXor, setTable]

theorem select_set_naive_counterexample :
    ∃ (T : Table) (k : Bool) (v : Val),
      select (set T k v) ≠ set (select T) k v := by
  -- Pick T ≡ 0, k=true, v=(hi=false, lo=true).
  let T : Table := fun _ => zeroVal
  let k : Bool := true
  let v : Val := (false, true)
  refine ⟨T, k, v, ?_⟩
  -- Show they differ at index k.
  intro hEq
  have hAt : select (set T k v) k = set (select T) k v k := by
    simpa using congrArg (fun f => f k) hEq
  -- LHS selects v, which has hi=false, so becomes 0.
  -- RHS sets k to v directly, which is (false,true) ≠ 0.
  -- Hence contradiction.
  simp [T, k, v, set, select, hi, zeroVal] at hAt

end Mprd.Tau.Tables

