/-!
# Policy Algebra: Veto Lifting (Lean spec + proof)

Generated-by: Codex (0x81e0a9e651e4e59d)
Date: 2025-12-26
Status: Auxiliary proof artifact (non-normative)

This file formalizes the "veto-first" semantics used by MPRD Policy Algebra (for total boolean
signal assignments) and proves that it is equivalent to the compilation strategy used by the
ROBDD rail:

  allow(expr) = (¬vetoTriggered(expr)) ∧ evalBool(eraseOrFalse(expr))

where:
- `DenyIf(atom)` declares a global veto guard on `atom`
- `eraseOrFalse` removes all `DenyIf(_)` nodes from the main formula (treating them as neutral)
  and yields `False` if the whole expression erased away

This aligns with the Rust implementation:
- `mprd_core::policy_algebra::evaluate` (veto-first evaluation)
- `mprd_core::policy_algebra::compile_allow_robdd` (strip deny-if + veto conjunction)
-/

namespace Mprd.PolicyAlgebra

abbrev Ctx := String → Bool

inductive Expr where
  | t : Expr
  | f : Expr
  | atom : String → Expr
  | not : Expr → Expr
  | all : List Expr → Expr
  | any : List Expr → Expr
  | denyIf : String → Expr
  deriving Repr

mutual
  def vetoAtoms : Expr → List String
    | .denyIf a => [a]
    | .not p => vetoAtoms p
    | .all xs => vetoAtomsList xs
    | .any xs => vetoAtomsList xs
    | .t | .f | .atom _ => []

  def vetoAtomsList : List Expr → List String
    | [] => []
    | e :: es => vetoAtoms e ++ vetoAtomsList es
end

def vetoTriggeredList (ctx : Ctx) : List String → Bool
  | [] => false
  | a :: as => ctx a || vetoTriggeredList ctx as

def vetoTriggered (ctx : Ctx) (e : Expr) : Bool :=
  vetoTriggeredList ctx (vetoAtoms e)

def eraseDenyIf : Expr → Option Expr
  | .denyIf _ => none
  | .t => some .t
  | .f => some .f
  | .atom a => some (.atom a)
  | .not p => (eraseDenyIf p).map Expr.not
  | .all xs => some (.all (xs.filterMap eraseDenyIf))
  | .any xs => some (.any (xs.filterMap eraseDenyIf))

def eraseOrFalse (e : Expr) : Expr :=
  (eraseDenyIf e).getD .f

mutual
  def evalBool (ctx : Ctx) : Expr → Bool
    | .t => true
    | .f => false
    | .atom a => ctx a
    | .not p => !(evalBool ctx p)
    | .all xs => evalAll ctx xs
    | .any xs => evalAny ctx xs
    | .denyIf _ => false

  def evalAll (ctx : Ctx) : List Expr → Bool
    | [] => true
    | e :: es => evalBool ctx e && evalAll ctx es

  def evalAny (ctx : Ctx) : List Expr → Bool
    | [] => false
    | e :: es => evalBool ctx e || evalAny ctx es
end

mutual
  def evalOpt (ctx : Ctx) : Expr → Option Bool
    | .t => some true
    | .f => some false
    | .atom a => some (ctx a)
    | .denyIf _ => none
    | .not p => (evalOpt ctx p).map (fun b => !b)
    | .all xs => some (evalAllOpt ctx xs)
    | .any xs => some (evalAnyOpt ctx xs)

  def evalAllOpt (ctx : Ctx) : List Expr → Bool
    | [] => true
    | e :: es => (evalOpt ctx e).getD true && evalAllOpt ctx es

  def evalAnyOpt (ctx : Ctx) : List Expr → Bool
    | [] => false
    | e :: es => (evalOpt ctx e).getD false || evalAnyOpt ctx es
end

def allowedMain (ctx : Ctx) (e : Expr) : Bool :=
  match evalOpt ctx e with
  | some true => true
  | _ => false

def allowedFull (ctx : Ctx) (e : Expr) : Bool :=
  if vetoTriggered ctx e then
    false
  else
    allowedMain ctx e

theorem evalOpt_eq_map_evalBool_eraseDenyIf (ctx : Ctx) :
    ∀ e : Expr, evalOpt ctx e = (eraseDenyIf e).map (fun e' => evalBool ctx e') := by
  intro e
  -- Use the nested recursor to induct over `Expr` and (structurally) over `List Expr`.
  refine Expr.recOn (t := e)
    (motive_1 := fun e => evalOpt ctx e = (eraseDenyIf e).map (fun e' => evalBool ctx e'))
    (motive_2 := fun xs =>
      (evalAllOpt ctx xs = evalAll ctx (xs.filterMap eraseDenyIf)) ∧
      (evalAnyOpt ctx xs = evalAny ctx (xs.filterMap eraseDenyIf)))
    ?t ?f ?atom ?not ?all ?any ?denyIf ?nil ?cons
  · simp [evalOpt, eraseDenyIf, evalBool]
  · simp [evalOpt, eraseDenyIf, evalBool]
  · intro a; simp [evalOpt, eraseDenyIf, evalBool]
  · intro p ih
    cases hErase : eraseDenyIf p with
    | none =>
        have : evalOpt ctx p = none := by
          simpa [hErase] using ih
        simp [evalOpt, eraseDenyIf, evalBool, hErase, this]
    | some p' =>
        have : evalOpt ctx p = some (evalBool ctx p') := by
          simpa [hErase] using ih
        simp [evalOpt, eraseDenyIf, evalBool, hErase, this]
  · intro xs ihList
    simp [evalOpt, eraseDenyIf, evalBool, ihList.left]
  · intro xs ihList
    simp [evalOpt, eraseDenyIf, evalBool, ihList.right]
  · intro a; simp [evalOpt, eraseDenyIf, evalBool]
  · exact And.intro rfl rfl
  · intro head tail ihHead ihTail
    constructor
    · -- `all`
      cases hErase : eraseDenyIf head with
      | none =>
          have : evalOpt ctx head = none := by
            simpa [hErase] using ihHead
          simp [evalAllOpt, evalAll, hErase, this, ihTail.left]
      | some head' =>
          have : evalOpt ctx head = some (evalBool ctx head') := by
            simpa [hErase] using ihHead
          simp [evalAllOpt, evalAll, hErase, this, ihTail.left]
    · -- `any`
      cases hErase : eraseDenyIf head with
      | none =>
          have : evalOpt ctx head = none := by
            simpa [hErase] using ihHead
          simp [evalAnyOpt, evalAny, hErase, this, ihTail.right]
      | some head' =>
          have : evalOpt ctx head = some (evalBool ctx head') := by
            simpa [hErase] using ihHead
          simp [evalAnyOpt, evalAny, hErase, this, ihTail.right]

theorem allowedMain_eq_evalBool_eraseOrFalse (ctx : Ctx) :
    ∀ e : Expr, allowedMain ctx e = evalBool ctx (eraseOrFalse e) := by
  intro e
  have h := evalOpt_eq_map_evalBool_eraseDenyIf ctx e
  cases hErase : eraseDenyIf e with
  | none =>
      -- `evalOpt e = none`, so `allowedMain = false` and `eraseOrFalse = False`.
      have : evalOpt ctx e = none := by
        simpa [hErase] using h
      simp [allowedMain, eraseOrFalse, hErase, this, evalBool]
  | some e' =>
      -- `evalOpt e = some (evalBool e')`.
      have : evalOpt ctx e = some (evalBool ctx e') := by
        simpa [hErase] using h
      cases hb : evalBool ctx e' <;> simp [allowedMain, eraseOrFalse, hErase, this, hb, evalBool]

theorem allowedFull_eq_compiledAllow (ctx : Ctx) :
    ∀ e : Expr,
      allowedFull ctx e = ((!vetoTriggered ctx e) && evalBool ctx (eraseOrFalse e)) := by
  intro e
  cases hv : vetoTriggered ctx e with
  | false =>
      simp [allowedFull, hv, allowedMain_eq_evalBool_eraseOrFalse]
  | true =>
      simp [allowedFull, hv]

end Mprd.PolicyAlgebra
