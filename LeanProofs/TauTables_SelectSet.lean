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

theorem select_set_refined (T : Table) (k : Bool) (v : Val) :
    select (set T k v) = set (select T) k (selectVal v) := by
  funext i
  by_cases h : i = k
  · -- At the updated key, `select` sees exactly `v`.
    -- Compute both sides at index `i` using `i=k`, then reduce to a Bool case split.
    have hL : select (set T k v) i = (if hi v then selectVal v else zeroVal) := by
      -- `set T k v i = v` under `i=k`
      simp [select, set, h, hi]
    have hR : set (select T) k (selectVal v) i = selectVal v := by
      simp [set, h]
    -- Rewrite the goal with hL/hR and split on `hi v`.
    rw [hL]
    -- rewrite the RHS to `selectVal v`
    rw [hR]
    -- Now the goal depends only on the concrete 2-bit value `v`.
    cases v with
    | mk a b =>
        cases a <;> cases b <;> simp [hi, lo, selectVal, zeroVal]
  · -- At other keys, both sides reduce to selecting the old value `T i`.
    simp [set, select, h, selectVal, hi, lo, zeroVal]

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

