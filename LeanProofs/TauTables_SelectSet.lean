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

