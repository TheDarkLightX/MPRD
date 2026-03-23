---- MODULE distributed_replay_split_brain_barrier ----
EXTENDS Naturals

Results == {"idle", "ready", "claimed", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

\* Intentionally narrow abstraction:
\* - two replica-local claim stores that stay coupled until a partition
\* - split-brain means stores may diverge under partition
\* - commit remains fail-closed and requires store agreement before execute
\* - conflict reconciliation clears ownership instead of picking a winning side
\* - this is a safety model only; it does not prove eventual recovery or liveness
VARIABLES ready1, ready2, partitioned, fresh1, fresh2,
          view1_owner, view2_owner, view1_epoch, view2_epoch,
          store1_owner, store2_owner, store1_epoch, store2_epoch,
          effect_count, result1, result2

StoresAgree ==
    /\ store1_owner = store2_owner
    /\ store1_epoch = store2_epoch

ReconcileEpoch ==
    IF store1_epoch >= store2_epoch
        THEN store1_epoch + 1
        ELSE store2_epoch + 1

Init ==
    /\ ready1 = FALSE
    /\ ready2 = FALSE
    /\ partitioned = FALSE
    /\ fresh1 = TRUE
    /\ fresh2 = TRUE
    /\ view1_owner = "none"
    /\ view2_owner = "none"
    /\ view1_epoch = 0
    /\ view2_epoch = 0
    /\ store1_owner = "none"
    /\ store2_owner = "none"
    /\ store1_epoch = 0
    /\ store2_epoch = 0
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
       /\ UNCHANGED <<ready2, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ ~ready2
       /\ result2 = "idle"
       /\ ready2' = TRUE
       /\ result2' = "ready"
       /\ UNCHANGED <<ready1, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result1>>
    \/ /\ Active
       /\ ~partitioned
       /\ partitioned' = TRUE
       /\ UNCHANGED <<ready1, ready2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ partitioned
       /\ StoresAgree
       /\ partitioned' = FALSE
       /\ UNCHANGED <<ready1, ready2, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ partitioned
       /\ ~StoresAgree
       /\ partitioned' = FALSE
       /\ store1_owner' = "none"
       /\ store2_owner' = "none"
       /\ store1_epoch' = ReconcileEpoch
       /\ store2_epoch' = ReconcileEpoch
       /\ fresh1' = FALSE
       /\ fresh2' = FALSE
       /\ result1' = IF result1 = "claimed" THEN "rejected" ELSE result1
       /\ result2' = IF result2 = "claimed" THEN "rejected" ELSE result2
       /\ UNCHANGED <<ready1, ready2, view1_owner, view2_owner,
                      view1_epoch, view2_epoch, effect_count>>
    \/ /\ Active
       /\ view1_owner' = store1_owner
       /\ view1_epoch' = store1_epoch
       /\ fresh1' = TRUE
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh2,
                      view2_owner, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ view2_owner' = store2_owner
       /\ view2_epoch' = store2_epoch
       /\ fresh2' = TRUE
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh1,
                      view1_owner, view1_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ fresh1
       /\ view1_owner = "none"
       /\ view1_epoch = store1_epoch
       /\ ~partitioned
       /\ StoresAgree
       /\ store1_owner = "none"
       /\ store1_owner' = "r1"
       /\ store2_owner' = "r1"
       /\ store1_epoch' = store1_epoch + 1
       /\ store2_epoch' = store2_epoch + 1
       /\ view1_owner' = "r1"
       /\ view1_epoch' = store1_epoch + 1
       /\ fresh1' = TRUE
       /\ fresh2' = FALSE
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, partitioned,
                      view2_owner, view2_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ fresh2
       /\ view2_owner = "none"
       /\ view2_epoch = store2_epoch
       /\ ~partitioned
       /\ StoresAgree
       /\ store2_owner = "none"
       /\ store1_owner' = "r2"
       /\ store2_owner' = "r2"
       /\ store1_epoch' = store1_epoch + 1
       /\ store2_epoch' = store2_epoch + 1
       /\ view2_owner' = "r2"
       /\ view2_epoch' = store2_epoch + 1
       /\ fresh2' = TRUE
       /\ fresh1' = FALSE
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, partitioned,
                      view1_owner, view1_epoch, effect_count, result1>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ fresh1
       /\ view1_owner = "none"
       /\ view1_epoch = store1_epoch
       /\ partitioned
       /\ store1_owner = "none"
       /\ store1_owner' = "r1"
       /\ store1_epoch' = store1_epoch + 1
       /\ view1_owner' = "r1"
       /\ view1_epoch' = store1_epoch + 1
       /\ fresh1' = TRUE
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh2,
                      view2_owner, view2_epoch,
                      store2_owner, store2_epoch, effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ fresh2
       /\ view2_owner = "none"
       /\ view2_epoch = store2_epoch
       /\ partitioned
       /\ store2_owner = "none"
       /\ store2_owner' = "r2"
       /\ store2_epoch' = store2_epoch + 1
       /\ view2_owner' = "r2"
       /\ view2_epoch' = store2_epoch + 1
       /\ fresh2' = TRUE
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh1,
                      view1_owner, view1_epoch,
                      store1_owner, store1_epoch, effect_count, result1>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ (~fresh1 \/ view1_owner # "none" \/ view1_epoch # store1_epoch
           \/ (~partitioned /\ (~StoresAgree \/ store1_owner # "none"))
           \/ (partitioned /\ store1_owner # "none"))
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ (~fresh2 \/ view2_owner # "none" \/ view2_epoch # store2_epoch
           \/ (~partitioned /\ (~StoresAgree \/ store2_owner # "none"))
           \/ (partitioned /\ store2_owner # "none"))
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result1>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ (~fresh1 \/ view1_owner # store1_owner \/ view1_epoch # store1_epoch
           \/ ~StoresAgree \/ store1_owner # "r1" \/ store2_owner # "r1")
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ (~fresh2 \/ view2_owner # store2_owner \/ view2_epoch # store2_epoch
           \/ ~StoresAgree \/ store1_owner # "r2" \/ store2_owner # "r2")
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result1>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ StoresAgree
       /\ store1_owner = "r1"
       /\ store2_owner = "r1"
       /\ fresh1
       /\ view1_owner = "r1"
       /\ view1_epoch = store1_epoch
       /\ effect_count = 0
       /\ result1' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ StoresAgree
       /\ store1_owner = "r2"
       /\ store2_owner = "r2"
       /\ fresh2
       /\ view2_owner = "r2"
       /\ view2_epoch = store2_epoch
       /\ effect_count = 0
       /\ result2' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      result1>>
    \/ /\ UNCHANGED <<ready1, ready2, partitioned, fresh1, fresh2,
                     view1_owner, view2_owner, view1_epoch, view2_epoch,
                     store1_owner, store2_owner, store1_epoch, store2_epoch,
                     effect_count, result1, result2>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvExecutedRequiresStoreAgreement ==
    /\ (result1 = "executed" =>
           /\ StoresAgree
           /\ store1_owner = "r1"
           /\ store2_owner = "r1"
           /\ fresh1
           /\ view1_owner = "r1"
           /\ view1_epoch = store1_epoch)
    /\ (result2 = "executed" =>
           /\ StoresAgree
           /\ store1_owner = "r2"
           /\ store2_owner = "r2"
           /\ fresh2
           /\ view2_owner = "r2"
           /\ view2_epoch = store2_epoch)

InvSplitBrainBlocksExecution ==
    ~StoresAgree => /\ result1 # "executed"
                    /\ result2 # "executed"

InvFreshViewMatchesLocalStore ==
    /\ (fresh1 => /\ view1_owner = store1_owner /\ view1_epoch = store1_epoch)
    /\ (fresh2 => /\ view2_owner = store2_owner /\ view2_epoch = store2_epoch)

InvStoreOwnersWellFormed ==
    /\ store1_owner \in Owners
    /\ store2_owner \in Owners

InvNoDualExecution ==
    ~((result1 = "executed") /\ (result2 = "executed"))

Spec ==
    Init /\ [][Next]_<<ready1, ready2, partitioned, fresh1, fresh2,
                      view1_owner, view2_owner, view1_epoch, view2_epoch,
                      store1_owner, store2_owner, store1_epoch, store2_epoch,
                      effect_count, result1, result2>>

====
