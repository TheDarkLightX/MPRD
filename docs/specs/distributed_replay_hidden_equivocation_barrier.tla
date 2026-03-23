---- MODULE distributed_replay_hidden_equivocation_barrier ----
EXTENDS Naturals

Results == {"idle", "ready", "claimed", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

\* Intentionally narrow abstraction:
\* - one actual quorum certificate per replica
\* - per-replica peer-certificate views can be stale or absent
\* - same-epoch conflicting certificates may exist before a fresh peer refresh
\* - execute requires a fresh peer view before trusting the local certificate
\* - this is a safety-only hidden-conflict barrier, not a liveness theorem
VARIABLES ready1, ready2,
          link12, link21,
          fresh12, fresh21,
          cert1_valid, cert1_owner, cert1_epoch,
          cert2_valid, cert2_owner, cert2_epoch,
          view12_valid, view12_owner, view12_epoch,
          view21_valid, view21_owner, view21_epoch,
          issued_epoch,
          effect_count, result1, result2

ActualSameEpochConflict ==
    /\ cert1_valid
    /\ cert2_valid
    /\ cert1_epoch = cert2_epoch
    /\ cert1_owner # cert2_owner

VisibleConflictTo1 ==
    /\ fresh12
    /\ cert1_valid
    /\ view12_valid
    /\ view12_epoch = cert1_epoch
    /\ view12_owner # cert1_owner

VisibleConflictTo2 ==
    /\ fresh21
    /\ cert2_valid
    /\ view21_valid
    /\ view21_epoch = cert2_epoch
    /\ view21_owner # cert2_owner

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
    /\ view12_valid = FALSE
    /\ view12_owner = "none"
    /\ view12_epoch = 0
    /\ view21_valid = FALSE
    /\ view21_owner = "none"
    /\ view21_epoch = 0
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
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result2>>
    \/ /\ Active
       /\ ~ready2
       /\ result2 = "idle"
       /\ ready2' = TRUE
       /\ result2' = "ready"
       /\ UNCHANGED <<ready1, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result1>>
    \/ /\ Active /\ link12 /\ link12' = FALSE /\ fresh12' = FALSE
       /\ UNCHANGED <<ready1, ready2, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ ~link12 /\ link12' = TRUE /\ fresh12' = FALSE
       /\ UNCHANGED <<ready1, ready2, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ link21 /\ link21' = FALSE /\ fresh21' = FALSE
       /\ UNCHANGED <<ready1, ready2, link12, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ ~link21 /\ link21' = TRUE /\ fresh21' = FALSE
       /\ UNCHANGED <<ready1, ready2, link12, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link12
       /\ view12_valid' = cert2_valid
       /\ view12_owner' = cert2_owner
       /\ view12_epoch' = cert2_epoch
       /\ fresh12' = TRUE
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link21
       /\ view21_valid' = cert1_valid
       /\ view21_owner' = cert1_owner
       /\ view21_epoch' = cert1_epoch
       /\ fresh21' = TRUE
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
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
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
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
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
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
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
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
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ VisibleConflictTo1
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ VisibleConflictTo2
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result1>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ cert1_valid
       /\ cert1_owner = "r1"
       /\ fresh12
       /\ ~VisibleConflictTo1
       /\ effect_count = 0
       /\ result1' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ cert2_valid
       /\ cert2_owner = "r2"
       /\ fresh21
       /\ ~VisibleConflictTo2
       /\ effect_count = 0
       /\ result2' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, result1>>
    \/ /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                     cert1_valid, cert1_owner, cert1_epoch,
                     cert2_valid, cert2_owner, cert2_epoch,
                     view12_valid, view12_owner, view12_epoch,
                     view21_valid, view21_owner, view21_epoch,
                     issued_epoch, effect_count, result1, result2>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvFreshViewsMatchActualPeerCert ==
    /\ (fresh12 =>
           /\ view12_valid = cert2_valid
           /\ view12_owner = cert2_owner
           /\ view12_epoch = cert2_epoch)
    /\ (fresh21 =>
           /\ view21_valid = cert1_valid
           /\ view21_owner = cert1_owner
           /\ view21_epoch = cert1_epoch)

InvExecutedRequiresFreshPeerViewNoConflict ==
    /\ (result1 = "executed" =>
           /\ cert1_valid
           /\ cert1_owner = "r1"
           /\ fresh12
           /\ ~VisibleConflictTo1)
    /\ (result2 = "executed" =>
           /\ cert2_valid
           /\ cert2_owner = "r2"
           /\ fresh21
           /\ ~VisibleConflictTo2)

InvHiddenConflictCannotExecuteWithoutFreshPeerView ==
    /\ ((ActualSameEpochConflict /\ ~fresh12) => result1 # "executed")
    /\ ((ActualSameEpochConflict /\ ~fresh21) => result2 # "executed")

InvOwnersWellFormed ==
    /\ cert1_owner \in Owners
    /\ cert2_owner \in Owners
    /\ view12_owner \in Owners
    /\ view21_owner \in Owners

InvNoDualExecution ==
    ~((result1 = "executed") /\ (result2 = "executed"))

Spec ==
    Init /\ [][Next]_<<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      view12_valid, view12_owner, view12_epoch,
                      view21_valid, view21_owner, view21_epoch,
                      issued_epoch, effect_count, result1, result2>>

====
