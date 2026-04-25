/-!
# Fail-Closed Hardening Obligations

This auxiliary Lean artifact formalizes the two security obligations hardened in
the Rust policy-algebra/CEGIS slice:

1. Negation may not convert missing evidence into an accepting policy result.
2. Reserved action-derived atoms have precedence over state-provided signals.

The model is intentionally small and checker-relative: it captures the semantic
contracts implemented by `policy_algebra::evaluate` and
`cegis::PolicyAlgebraVerifier::signal_for`, not the full Rust implementation.
-/

namespace Mprd.FailClosedHardening

inductive Outcome where
  | allow
  | denySoft
  | denyVeto
  | neutral
  deriving DecidableEq, Repr

abbrev Ctx := String → Option Bool

inductive Expr where
  | t
  | f
  | atom : String → Expr
  | denyIf : String → Expr
  | not : Expr → Expr
  | all : List Expr → Expr
  | any : List Expr → Expr
  deriving Repr

mutual
  def hasMissing (ctx : Ctx) : Expr → Bool
    | .atom a => (ctx a).isNone
    | .denyIf a => (ctx a).isNone
    | .not p => hasMissing ctx p
    | .all xs => hasMissingList ctx xs
    | .any xs => hasMissingList ctx xs
    | .t | .f => false

  def hasMissingList (ctx : Ctx) : List Expr → Bool
    | [] => false
    | x :: xs => hasMissing ctx x || hasMissingList ctx xs
end

def invertForNot : Outcome → Outcome
  | .allow => .denySoft
  | .denySoft => .allow
  | .denyVeto => .allow
  | .neutral => .neutral

mutual
  def eval (ctx : Ctx) : Expr → Outcome
    | .t => .allow
    | .f => .denySoft
    | .atom a =>
        match ctx a with
        | some true => .allow
        | some false => .denySoft
        | none => .denySoft
    | .denyIf _ => .neutral
    | .not p =>
        if hasMissing ctx p then
          .denySoft
        else
          invertForNot (eval ctx p)
    | .all xs => evalAll ctx xs
    | .any xs => evalAny ctx xs

  def evalAll (ctx : Ctx) : List Expr → Outcome
    | [] => .allow
    | x :: xs =>
        match eval ctx x with
        | .allow | .neutral => evalAll ctx xs
        | .denySoft => .denySoft
        | .denyVeto => .denyVeto

  def evalAny (ctx : Ctx) : List Expr → Outcome
    | [] => .denySoft
    | x :: xs =>
        match eval ctx x with
        | .allow => .allow
        | .denyVeto => .denyVeto
        | .denySoft | .neutral => evalAny ctx xs
end

theorem not_missing_subtree_is_deny_soft (ctx : Ctx) (p : Expr)
    (h : hasMissing ctx p = true) :
    eval ctx (.not p) = .denySoft := by
  simp [eval, h]

theorem not_of_missing_atom_is_deny_soft (ctx : Ctx) (a : String)
    (h : ctx a = none) :
    eval ctx (.not (.atom a)) = .denySoft := by
  simp [eval, hasMissing, h]

theorem not_of_nested_all_with_missing_child_is_deny_soft
    (ctx : Ctx) (missing present : String)
    (hMissing : ctx missing = none) :
    eval ctx (.not (.all [.atom missing, .atom present])) = .denySoft := by
  simp [eval, hasMissing, hasMissingList, hMissing]

inductive Step where
  | neg
  | zero
  | pos
  deriving DecidableEq, Repr

structure Action where
  db : Step
  da : Step
  dd : Step
  noop : Bool
  deriving Repr

abbrev StateSignals := String → Option Bool

def actionSignal (action : Action) (atom : String) : Option Bool :=
  match atom with
  | "action_noop" => some action.noop
  | "action_db_neg" => some (action.db == .neg)
  | "action_db_zero" => some (action.db == .zero)
  | "action_db_pos" => some (action.db == .pos)
  | "action_da_neg" => some (action.da == .neg)
  | "action_da_zero" => some (action.da == .zero)
  | "action_da_pos" => some (action.da == .pos)
  | "action_dd_neg" => some (action.dd == .neg)
  | "action_dd_zero" => some (action.dd == .zero)
  | "action_dd_pos" => some (action.dd == .pos)
  | _ => none

def signalFor (state : StateSignals) (action : Action) (atom : String) : Option Bool :=
  match actionSignal action atom with
  | some v => some v
  | none => state atom

theorem reserved_action_signal_has_precedence
    (state : StateSignals) (action : Action) (atom : String) (v : Bool)
    (h : actionSignal action atom = some v) :
    signalFor state action atom = some v := by
  simp [signalFor, h]

theorem action_db_pos_true_ignores_state_spoof
    (state : StateSignals) (da dd : Step) (noop : Bool) :
    signalFor state
      { db := .pos, da := da, dd := dd, noop := noop }
      "action_db_pos" = some true := by
  simp [signalFor, actionSignal]

theorem action_db_pos_false_ignores_state_spoof
    (state : StateSignals) (db da dd : Step) (noop : Bool)
    (h : db ≠ .pos) :
    signalFor state
      { db := db, da := da, dd := dd, noop := noop }
      "action_db_pos" = some false := by
  cases db <;> simp [signalFor, actionSignal] at *

end Mprd.FailClosedHardening
