---- MODULE distributed_replay_equivocation_recovery_barrier ----
EXTENDS Naturals

Results == {"idle", "ready", "claimed", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

\* Intentionally narrow abstraction:
\* - one quorum certificate per replica
\* - conflicting same-epoch certificates may exist and later become visible
\* - a recovery step clears both certificates and bumps a resolution epoch
\* - only fresh post-resolution certificates may cross the execute barrier
\* - this is a recovery-safety packet, not a liveness theorem
VARIABLES ready1, ready2,
          link12, link21,
          fresh12, fresh21,
          cert1_valid, cert1_owner, cert1_epoch,
          cert2_valid, cert2_owner, cert2_epoch,
          issued_epoch, resolved_epoch,
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

RecoveryEpoch ==
    IF cert1_epoch >= cert2_epoch
        THEN cert1_epoch + 1
        ELSE cert2_epoch + 1

ClaimEpoch ==
    IF issued_epoch >= resolved_epoch
        THEN issued_epoch + 1
        ELSE resolved_epoch + 1

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
    /\ resolved_epoch = 0
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
                      issued_epoch, resolved_epoch, effect_count, result2>>
    \/ /\ Active
       /\ ~ready2
       /\ result2 = "idle"
       /\ ready2' = TRUE
       /\ result2' = "ready"
       /\ UNCHANGED <<ready1, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, effect_count, result1>>
    \/ /\ Active /\ link12 /\ link12' = FALSE /\ fresh12' = FALSE
       /\ UNCHANGED <<ready1, ready2, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ ~link12 /\ link12' = TRUE /\ fresh12' = FALSE
       /\ UNCHANGED <<ready1, ready2, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ link21 /\ link21' = FALSE /\ fresh21' = FALSE
       /\ UNCHANGED <<ready1, ready2, link12, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, effect_count, result1, result2>>
    \/ /\ Active /\ ~link21 /\ link21' = TRUE /\ fresh21' = FALSE
       /\ UNCHANGED <<ready1, ready2, link12, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link12
       /\ fresh12' = TRUE
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link21
       /\ fresh21' = TRUE
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ ~cert1_valid
       /\ cert1_valid' = TRUE
       /\ cert1_owner' = "r1"
       /\ cert1_epoch' = ClaimEpoch
       /\ issued_epoch' = ClaimEpoch
       /\ fresh21' = FALSE
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12,
                      cert2_valid, cert2_owner, cert2_epoch,
                      resolved_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ ~cert2_valid
       /\ cert2_valid' = TRUE
       /\ cert2_owner' = "r2"
       /\ cert2_epoch' = ClaimEpoch
       /\ issued_epoch' = ClaimEpoch
       /\ fresh12' = FALSE
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      resolved_epoch, effect_count, result1>>
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
                      issued_epoch, resolved_epoch, effect_count, result1>>
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
                      issued_epoch, resolved_epoch, effect_count, result2>>
    \/ /\ Active
       /\ ConflictVisibleTo1 \/ ConflictVisibleTo2
       /\ cert1_valid' = FALSE
       /\ cert2_valid' = FALSE
       /\ resolved_epoch' = RecoveryEpoch
       /\ issued_epoch' = RecoveryEpoch
       /\ fresh12' = FALSE
       /\ fresh21' = FALSE
       /\ result1' = IF result1 = "claimed" THEN "rejected" ELSE result1
       /\ result2' = IF result2 = "claimed" THEN "rejected" ELSE result2
       /\ UNCHANGED <<ready1, ready2, link12, link21,
                      cert1_owner, cert1_epoch, cert2_owner, cert2_epoch,
                      effect_count>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ cert1_valid
       /\ cert1_owner = "r1"
       /\ cert1_epoch > resolved_epoch
       /\ fresh12
       /\ ~ConflictVisibleTo1
       /\ effect_count = 0
       /\ result1' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ cert2_valid
       /\ cert2_owner = "r2"
       /\ cert2_epoch > resolved_epoch
       /\ fresh21
       /\ ~ConflictVisibleTo2
       /\ effect_count = 0
       /\ result2' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      issued_epoch, resolved_epoch, result1>>
    \/ /\ UNCHANGED <<ready1, ready2, link12, link21, fresh12, fresh21,
                     cert1_valid, cert1_owner, cert1_epoch,
                     cert2_valid, cert2_owner, cert2_epoch,
                     issued_epoch, resolved_epoch, effect_count, result1, result2>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvExecutedRequiresPostResolutionFreshCert ==
    /\ (result1 = "executed" =>
           /\ cert1_valid
           /\ cert1_owner = "r1"
           /\ cert1_epoch > resolved_epoch
           /\ fresh12
           /\ ~ConflictVisibleTo1)
    /\ (result2 = "executed" =>
           /\ cert2_valid
           /\ cert2_owner = "r2"
           /\ cert2_epoch > resolved_epoch
           /\ fresh21
           /\ ~ConflictVisibleTo2)

InvResolvedNeverExceedsIssued ==
    resolved_epoch <= issued_epoch

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
                      issued_epoch, resolved_epoch, effect_count, result1, result2>>

====
