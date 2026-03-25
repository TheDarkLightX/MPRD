---- MODULE distributed_effect_finalization_barrier ----
EXTENDS Naturals

Results == {"idle", "ready", "claimed", "effect_emitted", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

\* Intentionally narrow abstraction:
\* - one logical effect id, with an initial attempt and one retry attempt
\* - a durable effect-commit barrier is written atomically with the first
\*   external effect emission
\* - nonce finalization may lag behind effect emission and may complete only
\*   after crash or recovery
\* - retries may reacquire claim before finalization, but they re-check the
\*   durable effect-commit barrier before emitting any new effect
\* - no liveness claims, no replicated effect log, and no multi-effect batch
VARIABLES result1, result2, executor_up, claim_owner,
          effect_committed, nonce_finalized, effect_count

Init ==
    /\ result1 = "idle"
    /\ result2 = "idle"
    /\ executor_up = TRUE
    /\ claim_owner = "none"
    /\ effect_committed = FALSE
    /\ nonce_finalized = FALSE
    /\ effect_count = 0

Next ==
    \/ /\ result1 = "idle"
       /\ result1' = "ready"
       /\ UNCHANGED <<result2, executor_up, claim_owner,
                      effect_committed, nonce_finalized, effect_count>>
    \/ /\ result2 = "idle"
       /\ result2' = "ready"
       /\ UNCHANGED <<result1, executor_up, claim_owner,
                      effect_committed, nonce_finalized, effect_count>>
    \/ /\ result1 = "ready"
       /\ executor_up
       /\ ~nonce_finalized
       /\ claim_owner = "none"
       /\ claim_owner' = "r1"
       /\ result1' = "claimed"
       /\ UNCHANGED <<result2, executor_up, effect_committed,
                      nonce_finalized, effect_count>>
    \/ /\ result2 = "ready"
       /\ executor_up
       /\ ~nonce_finalized
       /\ claim_owner = "none"
       /\ claim_owner' = "r2"
       /\ result2' = "claimed"
       /\ UNCHANGED <<result1, executor_up, effect_committed,
                      nonce_finalized, effect_count>>
    \/ /\ result1 = "claimed"
       /\ executor_up
       /\ claim_owner = "r1"
       /\ ~effect_committed
       /\ effect_count = 0
       /\ effect_committed' = TRUE
       /\ effect_count' = 1
       /\ result1' = "effect_emitted"
       /\ UNCHANGED <<result2, executor_up, claim_owner, nonce_finalized>>
    \/ /\ result2 = "claimed"
       /\ executor_up
       /\ claim_owner = "r2"
       /\ ~effect_committed
       /\ effect_count = 0
       /\ effect_committed' = TRUE
       /\ effect_count' = 1
       /\ result2' = "effect_emitted"
       /\ UNCHANGED <<result1, executor_up, claim_owner, nonce_finalized>>
    \/ /\ executor_up
       /\ effect_committed
       /\ ~nonce_finalized
       /\ executor_up' = FALSE
       /\ claim_owner' = "none"
       /\ UNCHANGED <<result1, result2, effect_committed,
                      nonce_finalized, effect_count>>
    \/ /\ ~executor_up
       /\ executor_up' = TRUE
       /\ UNCHANGED <<result1, result2, claim_owner,
                      effect_committed, nonce_finalized, effect_count>>
    \/ /\ result1 = "effect_emitted"
       /\ executor_up
       /\ effect_committed
       /\ ~nonce_finalized
       /\ nonce_finalized' = TRUE
       /\ claim_owner' = "none"
       /\ result1' = "executed"
       /\ UNCHANGED <<result2, executor_up, effect_committed, effect_count>>
    \/ /\ result2 = "effect_emitted"
       /\ executor_up
       /\ effect_committed
       /\ ~nonce_finalized
       /\ nonce_finalized' = TRUE
       /\ claim_owner' = "none"
       /\ result2' = "executed"
       /\ UNCHANGED <<result1, executor_up, effect_committed, effect_count>>
    \/ /\ result1 = "claimed"
       /\ executor_up
       /\ (effect_committed \/ nonce_finalized \/ claim_owner # "r1")
       /\ result1' = "rejected"
       /\ claim_owner' = IF claim_owner = "r1" THEN "none" ELSE claim_owner
       /\ UNCHANGED <<result2, executor_up, effect_committed,
                      nonce_finalized, effect_count>>
    \/ /\ result2 = "claimed"
       /\ executor_up
       /\ (effect_committed \/ nonce_finalized \/ claim_owner # "r2")
       /\ result2' = "rejected"
       /\ claim_owner' = IF claim_owner = "r2" THEN "none" ELSE claim_owner
       /\ UNCHANGED <<result1, executor_up, effect_committed,
                      nonce_finalized, effect_count>>
    \/ /\ UNCHANGED <<result1, result2, executor_up, claim_owner,
                      effect_committed, nonce_finalized, effect_count>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvCommittedEffectMatchesCount ==
    effect_committed => effect_count = 1

InvFinalizedRequiresCommittedEffect ==
    nonce_finalized => effect_committed

InvExecutedRequiresCommittedAndFinalized ==
    /\ (result1 = "executed" => effect_committed /\ nonce_finalized)
    /\ (result2 = "executed" => effect_committed /\ nonce_finalized)

InvNoDualExecution ==
    ~((result1 = "executed") /\ (result2 = "executed"))

InvResultsAndOwnerWellFormed ==
    /\ result1 \in Results
    /\ result2 \in Results
    /\ claim_owner \in Owners

Spec ==
    Init /\ [][Next]_<<result1, result2, executor_up, claim_owner,
                      effect_committed, nonce_finalized, effect_count>>

====
