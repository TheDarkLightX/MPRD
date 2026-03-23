---- MODULE distributed_replay_lease_barrier ----
EXTENDS Naturals

Results == {"idle", "ready", "claimed", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

\* Intentionally narrow abstraction:
\* - one atomic shared claim service
\* - per-replica connectivity, freshness, and owner plus epoch views
\* - claim acquisition and the claimant's fresh local view update are atomic
\* - lease expiry or revocation only clears the shared owner; no split-brain store
\* - although epochs range over Naturals, this packet stays finite because result
\*   states are one-shot and each replica can claim at most once
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
       /\ actual_owner # "none"
       \* Defense in depth: Active already blocks this after execution.
       /\ effect_count = 0
       /\ actual_owner' = "none"
       /\ actual_epoch' = actual_epoch + 1
       /\ fresh1' = FALSE
       /\ fresh2' = FALSE
       /\ result1' = IF result1 = "claimed" THEN "rejected" ELSE result1
       /\ result2' = IF result2 = "claimed" THEN "rejected" ELSE result2
       /\ UNCHANGED <<ready1, ready2, link1, link2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      effect_count>>
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
