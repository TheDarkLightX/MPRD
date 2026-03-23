---- MODULE distributed_replay_quorum_equivocation_barrier ----
EXTENDS Naturals

Results == {"idle", "ready", "claimed", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

\* Intentionally narrow abstraction:
\* - one quorum certificate per replica
\* - conflicting same-epoch quorum certificates may exist due to equivocation
\* - peer-certificate visibility is explicit and can become stale
\* - commit requires fresh peer-certificate visibility and rejects on visible conflict
\* - effect_count still models the earlier serial commit barrier for at-most-once
\*   execution across different-epoch concurrent claims
\* - this is a safety-only barrier model; it does not prove liveness or
\*   invisible-conflict detection
VARIABLES ready1, ready2,
          link12, link21,
          fresh12, fresh21,
          cert1_valid, cert1_owner, cert1_epoch,
          cert2_valid, cert2_owner, cert2_epoch,
          issued_epoch,
          effect_count, result1, result2

ConflictVisibleTo1 ==
    /\ fresh12
    /\ cert1_valid
    /\ cert2_valid
    /\ cert1_epoch = cert2_epoch
    /\ cert1_owner # cert2_owner

ConflictVisibleTo2 ==
    /\ fresh21
    /\ cert1_valid
    /\ cert2_valid
    /\ cert1_epoch = cert2_epoch
    /\ cert1_owner # cert2_owner

Init ==
    /\ ready1 = FALSE
    /\ ready2 = FALSE
    /\ link12 = TRUE
    /\ link21 = TRUE
    /\ fresh12 = TRUE
    /\ fresh21 = TRUE
    /\ cert1_valid = FALSE
    /\ cert1_owner = "none"
    /\ cert1_epoch = 0
    /\ cert2_valid = FALSE
    /\ cert2_owner = "none"
    /\ cert2_epoch = 0
    /\ issued_epoch = 0
    /\ effect_count = 0
    /\ result1 = "idle"
    /\ result2 = "idle"

Active ==
    /\ result1 # "executed"
    /\ result2 # "executed"

Next ==
    \/ /\ Active
       /\ ~ready1
       /\ result1 = "idle"
       /\ ready1' = TRUE
       /\ result1' = "ready"
       /\ UNCHANGED <<ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result2>>
    \/ /\ Active
       /\ ~ready2
       /\ result2 = "idle"
       /\ ready2' = TRUE
       /\ result2' = "ready"
       /\ UNCHANGED <<ready1, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1>>
    \/ /\ Active /\ link12 /\ link12' = FALSE /\ fresh12' = FALSE
       /\ UNCHANGED <<ready1, ready2, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ ~link12 /\ link12' = TRUE /\ fresh12' = FALSE
       /\ UNCHANGED <<ready1, ready2, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ link21 /\ link21' = FALSE /\ fresh21' = FALSE
       /\ UNCHANGED <<ready1, ready2, link12, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ ~link21 /\ link21' = TRUE /\ fresh21' = FALSE
       /\ UNCHANGED <<ready1, ready2, link12, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link12
       /\ fresh12' = TRUE
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link21
       /\ fresh21' = TRUE
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ ~cert1_valid
       /\ cert1_valid' = TRUE
       /\ cert1_owner' = "r1"
       /\ cert1_epoch' = issued_epoch + 1
       /\ issued_epoch' = issued_epoch + 1
       /\ fresh21' = FALSE
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ ~cert2_valid
       /\ cert2_valid' = TRUE
       /\ cert2_owner' = "r2"
       /\ cert2_epoch' = issued_epoch + 1
       /\ issued_epoch' = issued_epoch + 1
       /\ fresh12' = FALSE
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      effect_count, result1>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ cert1_valid
       /\ ~cert2_valid
       /\ cert1_owner = "r1"
       /\ cert2_valid' = TRUE
       /\ cert2_owner' = "r2"
       /\ cert2_epoch' = cert1_epoch
       /\ fresh12' = FALSE
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      issued_epoch, effect_count, result1>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ cert2_valid
       /\ ~cert1_valid
       /\ cert2_owner = "r2"
       /\ cert1_valid' = TRUE
       /\ cert1_owner' = "r1"
       /\ cert1_epoch' = cert2_epoch
       /\ fresh21' = FALSE
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ ConflictVisibleTo1
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ ConflictVisibleTo2
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ cert1_valid
       /\ cert1_owner = "r1"
       /\ fresh12
       /\ ~ConflictVisibleTo1
       /\ effect_count = 0
       /\ result1' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ cert2_valid
       /\ cert2_owner = "r2"
       /\ fresh21
       /\ ~ConflictVisibleTo2
       /\ effect_count = 0
       /\ result2' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, result1>>
    \/ /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                     cert1_valid, cert1_owner, cert1_epoch,
                     cert2_valid, cert2_owner, cert2_epoch,
                     issued_epoch, effect_count, result1, result2>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvExecutedRequiresFreshNoConflict ==
    /\ (result1 = "executed" =>
           /\ cert1_valid
           /\ cert1_owner = "r1"
           /\ fresh12
           /\ ~ConflictVisibleTo1)
    /\ (result2 = "executed" =>
           /\ cert2_valid
           /\ cert2_owner = "r2"
           /\ fresh21
           /\ ~ConflictVisibleTo2)

InvVisibleConflictBlocksExecution ==
    /\ (ConflictVisibleTo1 => result1 # "executed")
    /\ (ConflictVisibleTo2 => result2 # "executed")

InvCertOwnersWellFormed ==
    /\ cert1_owner \in Owners
    /\ cert2_owner \in Owners

InvNoDualExecution ==
    ~((result1 = "executed") /\ (result2 = "executed"))

Spec ==
    Init /\ [][Next]_<<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, effect_count, result1, result2>>

====
