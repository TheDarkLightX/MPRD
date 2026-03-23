---- MODULE distributed_replay_claim_barrier ----
EXTENDS Naturals, Sequences

Results == {"idle", "ready", "claimed", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

VARIABLES ready1, ready2, partitioned, claim_store_up, claim_owner,
          effect_count, result1, result2

ClaimAvailable ==
    /\ ~partitioned
    /\ claim_store_up

Init ==
    /\ ready1 = FALSE
    /\ ready2 = FALSE
    /\ partitioned = FALSE
    /\ claim_store_up = TRUE
    /\ claim_owner = "none"
    /\ effect_count = 0
    /\ result1 = "idle"
    /\ result2 = "idle"

Next ==
    \/ /\ ~ready1
       /\ result1 = "idle"
       /\ ready1' = TRUE
       /\ result1' = "ready"
       /\ UNCHANGED <<ready2, partitioned, claim_store_up, claim_owner,
                      effect_count, result2>>
    \/ /\ ~ready2
       /\ result2 = "idle"
       /\ ready2' = TRUE
       /\ result2' = "ready"
       /\ UNCHANGED <<ready1, partitioned, claim_store_up, claim_owner,
                      effect_count, result1>>
    \/ /\ ~partitioned
       /\ partitioned' = TRUE
       /\ claim_store_up' = FALSE
       /\ UNCHANGED <<ready1, ready2, claim_owner, effect_count, result1, result2>>
    \/ /\ partitioned
       /\ partitioned' = FALSE
       /\ UNCHANGED <<ready1, ready2, claim_store_up, claim_owner, effect_count, result1, result2>>
    \/ /\ claim_store_up
       /\ claim_store_up' = FALSE
       /\ UNCHANGED <<ready1, ready2, partitioned, claim_owner, effect_count, result1, result2>>
    \/ /\ ~claim_store_up
       /\ ~partitioned
       /\ claim_store_up' = TRUE
       /\ UNCHANGED <<ready1, ready2, partitioned, claim_owner, effect_count, result1, result2>>
    \/ /\ result1 = "ready"
       /\ ClaimAvailable
       /\ claim_owner = "none"
       /\ claim_owner' = "r1"
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, partitioned, claim_store_up, effect_count, result2>>
    \/ /\ result2 = "ready"
       /\ ClaimAvailable
       /\ claim_owner = "none"
       /\ claim_owner' = "r2"
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, partitioned, claim_store_up, effect_count, result1>>
    \/ /\ result1 = "ready"
       /\ (~ClaimAvailable \/ claim_owner # "none")
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2, partitioned, claim_store_up, claim_owner, effect_count, result2>>
    \/ /\ result2 = "ready"
       /\ (~ClaimAvailable \/ claim_owner # "none")
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2, partitioned, claim_store_up, claim_owner, effect_count, result1>>
    \/ /\ result1 = "claimed"
       /\ claim_owner = "r1"
       /\ effect_count = 0
       /\ result1' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, partitioned, claim_store_up, claim_owner, result2>>
    \/ /\ result2 = "claimed"
       /\ claim_owner = "r2"
       /\ effect_count = 0
       /\ result2' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, partitioned, claim_store_up, claim_owner, result1>>
    \/ /\ UNCHANGED <<ready1, ready2, partitioned, claim_store_up, claim_owner, effect_count, result1, result2>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvExecutedRequiresClaimOwner ==
    /\ (result1 = "executed" => claim_owner = "r1")
    /\ (result2 = "executed" => claim_owner = "r2")

InvClaimOwnerUnique ==
    claim_owner \in Owners

InvNoDualExecution ==
    ~((result1 = "executed") /\ (result2 = "executed"))

Spec ==
    Init /\ [][Next]_<<ready1, ready2, partitioned, claim_store_up,
                      claim_owner, effect_count, result1, result2>>

====
