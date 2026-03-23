---- MODULE distributed_replay_direct_handoff_barrier ----
EXTENDS Naturals

Results == {"idle", "ready", "claimed", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

\* Intentionally narrow abstraction:
\* - one atomic shared claim service
\* - per-replica connectivity, freshness, and owner plus epoch views
\* - direct owner-to-owner handoff is allowed without clearing through "none"
\* - handoff increments the shared epoch, rejects the old claimed owner, and
\*   gives the recipient a fresh owner-plus-epoch view atomically
\* - no split-brain store behavior and no liveness claims
VARIABLES ready1, ready2, link1, link2, fresh1, fresh2,
          view1_owner, view2_owner, view1_epoch, view2_epoch,
          actual_owner, actual_epoch,
          effect_count, result1, result2

Init ==
    /\ ready1 = FALSE
    /\ ready2 = FALSE
    /\ link1 = TRUE
    /\ link2 = TRUE
    /\ fresh1 = TRUE
    /\ fresh2 = TRUE
    /\ view1_owner = "none"
    /\ view2_owner = "none"
    /\ view1_epoch = 0
    /\ view2_epoch = 0
    /\ actual_owner = "none"
    /\ actual_epoch = 0
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
       /\ UNCHANGED <<ready2, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result2>>
    \/ /\ Active
       /\ ~ready2
       /\ result2 = "idle"
       /\ ready2' = TRUE
       /\ result2' = "ready"
       /\ UNCHANGED <<ready1, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1>>
    \/ /\ Active
       /\ link1
       /\ link1' = FALSE
       /\ fresh1' = FALSE
       /\ UNCHANGED <<ready1, ready2, link2, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ ~link1
       /\ link1' = TRUE
       /\ fresh1' = FALSE
       /\ UNCHANGED <<ready1, ready2, link2, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link2
       /\ link2' = FALSE
       /\ fresh2' = FALSE
       /\ UNCHANGED <<ready1, ready2, link1, fresh1,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ ~link2
       /\ link2' = TRUE
       /\ fresh2' = FALSE
       /\ UNCHANGED <<ready1, ready2, link1, fresh1,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link1
       /\ view1_owner' = actual_owner
       /\ view1_epoch' = actual_epoch
       /\ fresh1' = TRUE
       /\ UNCHANGED <<ready1, ready2, link1, link2, fresh2,
                      view2_owner, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ link2
       /\ view2_owner' = actual_owner
       /\ view2_epoch' = actual_epoch
       /\ fresh2' = TRUE
       /\ UNCHANGED <<ready1, ready2, link1, link2, fresh1,
                      view1_owner, view1_epoch,
                      actual_owner, actual_epoch, effect_count, result1, result2>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ link1
       /\ fresh1
       /\ view1_owner = "none"
       /\ view1_epoch = actual_epoch
       /\ actual_owner = "none"
       /\ actual_owner' = "r1"
       /\ actual_epoch' = actual_epoch + 1
       /\ view1_owner' = "r1"
       /\ view1_epoch' = actual_epoch + 1
       /\ fresh1' = TRUE
       /\ fresh2' = FALSE
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1, link2,
                      view2_owner, view2_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ link2
       /\ fresh2
       /\ view2_owner = "none"
       /\ view2_epoch = actual_epoch
       /\ actual_owner = "none"
       /\ actual_owner' = "r2"
       /\ actual_epoch' = actual_epoch + 1
       /\ view2_owner' = "r2"
       /\ view2_epoch' = actual_epoch + 1
       /\ fresh2' = TRUE
       /\ fresh1' = FALSE
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1, link2,
                      view1_owner, view1_epoch, effect_count, result1>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ result2 = "ready"
       /\ actual_owner = "r1"
       /\ link2
       /\ fresh2
       /\ view2_owner = "r1"
       /\ view2_epoch = actual_epoch
       /\ actual_owner' = "r2"
       /\ actual_epoch' = actual_epoch + 1
       /\ view2_owner' = "r2"
       /\ view2_epoch' = actual_epoch + 1
       /\ fresh2' = TRUE
       /\ fresh1' = FALSE
       /\ result1' = "rejected"
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1, link2, effect_count, view1_owner, view1_epoch>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ result1 = "ready"
       /\ actual_owner = "r2"
       /\ link1
       /\ fresh1
       /\ view1_owner = "r2"
       /\ view1_epoch = actual_epoch
       /\ actual_owner' = "r1"
       /\ actual_epoch' = actual_epoch + 1
       /\ view1_owner' = "r1"
       /\ view1_epoch' = actual_epoch + 1
       /\ fresh1' = TRUE
       /\ fresh2' = FALSE
       /\ result2' = "rejected"
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1, link2, effect_count, view2_owner, view2_epoch>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ (~link1 \/ ~fresh1 \/ view1_owner # "none" \/ view1_epoch # actual_epoch
           \/ actual_owner # "none")
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ (~link2 \/ ~fresh2 \/ view2_owner # "none" \/ view2_epoch # actual_epoch
           \/ actual_owner # "none")
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ (~link1 \/ ~fresh1 \/ view1_owner # "r1" \/ view1_epoch # actual_epoch
           \/ actual_owner # "r1")
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ (~link2 \/ ~fresh2 \/ view2_owner # "r2" \/ view2_epoch # actual_epoch
           \/ actual_owner # "r2")
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1>>
    \* Execute still reads the shared owner plus epoch directly, but only after
    \* the local fresh-view equality checks have already forced agreement.
    \/ /\ Active
       /\ result1 = "claimed"
       /\ actual_owner = "r1"
       /\ fresh1
       /\ view1_owner = "r1"
       /\ view1_epoch = actual_epoch
       /\ effect_count = 0
       /\ result1' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ actual_owner = "r2"
       /\ fresh2
       /\ view2_owner = "r2"
       /\ view2_epoch = actual_epoch
       /\ effect_count = 0
       /\ result2' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, result1>>
    \/ /\ UNCHANGED <<ready1, ready2, link1, link2, fresh1, fresh2,
                     view1_owner, view2_owner, view1_epoch, view2_epoch,
                     actual_owner, actual_epoch, effect_count, result1, result2>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvExecutedRequiresActualOwner ==
    /\ (result1 = "executed" => actual_owner = "r1")
    /\ (result2 = "executed" => actual_owner = "r2")

InvExecutedRequiresFreshEpochMatchedView ==
    /\ (result1 = "executed" => /\ fresh1 /\ view1_owner = "r1" /\ view1_epoch = actual_epoch)
    /\ (result2 = "executed" => /\ fresh2 /\ view2_owner = "r2" /\ view2_epoch = actual_epoch)

InvClaimedOrExecutedRequiresCurrentOwner ==
    /\ (result1 \in {"claimed", "executed"} => actual_owner = "r1")
    /\ (result2 \in {"claimed", "executed"} => actual_owner = "r2")

InvFreshViewMatchesActualLease ==
    /\ (fresh1 => /\ view1_owner = actual_owner /\ view1_epoch = actual_epoch)
    /\ (fresh2 => /\ view2_owner = actual_owner /\ view2_epoch = actual_epoch)

InvActualOwnerWellFormed ==
    actual_owner \in Owners

InvNoDualExecution ==
    ~((result1 = "executed") /\ (result2 = "executed"))

Spec ==
    Init /\ [][Next]_<<ready1, ready2, link1, link2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      actual_owner, actual_epoch, effect_count, result1, result2>>

====
