---- MODULE distributed_replay_quorum_barrier ----
EXTENDS Naturals

Results == {"idle", "ready", "claimed", "executed", "rejected"}
Owners == {"none", "r1", "r2"}

\* Intentionally narrow abstraction:
\* - one 2-of-3 quorum-backed claim service
\* - stores may lag if a claimant cannot reach every replica, but claims and
\*   execution require a current quorum, not unanimous agreement
\* - local quorum certificates can become stale; execute re-checks current quorum
\* - no Byzantine stores, no direct owner handoff, and no liveness claims
VARIABLES ready1, ready2,
          link1q1, link1q2, link1q3,
          link2q1, link2q2, link2q3,
          q1_owner, q2_owner, q3_owner,
          q1_epoch, q2_epoch, q3_epoch,
          cert1_valid, cert1_owner, cert1_epoch,
          cert2_valid, cert2_owner, cert2_epoch,
          effect_count, result1, result2

HasQuorum(a, b, c) ==
    \/ (a /\ b)
    \/ (a /\ c)
    \/ (b /\ c)

QuorumFor1(owner, epoch) ==
    HasQuorum(
        link1q1 /\ q1_owner = owner /\ q1_epoch = epoch,
        link1q2 /\ q2_owner = owner /\ q2_epoch = epoch,
        link1q3 /\ q3_owner = owner /\ q3_epoch = epoch
    )

QuorumFor2(owner, epoch) ==
    HasQuorum(
        link2q1 /\ q1_owner = owner /\ q1_epoch = epoch,
        link2q2 /\ q2_owner = owner /\ q2_epoch = epoch,
        link2q3 /\ q3_owner = owner /\ q3_epoch = epoch
    )

Init ==
    /\ ready1 = FALSE
    /\ ready2 = FALSE
    /\ link1q1 = TRUE
    /\ link1q2 = TRUE
    /\ link1q3 = TRUE
    /\ link2q1 = TRUE
    /\ link2q2 = TRUE
    /\ link2q3 = TRUE
    /\ q1_owner = "none"
    /\ q2_owner = "none"
    /\ q3_owner = "none"
    /\ q1_epoch = 0
    /\ q2_epoch = 0
    /\ q3_epoch = 0
    /\ cert1_valid = FALSE
    /\ cert1_owner = "none"
    /\ cert1_epoch = 0
    /\ cert2_valid = FALSE
    /\ cert2_owner = "none"
    /\ cert2_epoch = 0
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
       /\ UNCHANGED <<ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ ~ready2
       /\ result2 = "idle"
       /\ ready2' = TRUE
       /\ result2' = "ready"
       /\ UNCHANGED <<ready1,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1>>
    \/ /\ Active /\ link1q1 /\ link1q1' = FALSE
       /\ UNCHANGED <<ready1, ready2, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ ~link1q1 /\ link1q1' = TRUE
       /\ UNCHANGED <<ready1, ready2, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ link1q2 /\ link1q2' = FALSE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ ~link1q2 /\ link1q2' = TRUE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ link1q3 /\ link1q3' = FALSE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ ~link1q3 /\ link1q3' = TRUE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ link2q1 /\ link2q1' = FALSE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ ~link2q1 /\ link2q1' = TRUE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ link2q2 /\ link2q2' = FALSE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ ~link2q2 /\ link2q2' = TRUE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ link2q3 /\ link2q3' = FALSE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q2,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active /\ ~link2q3 /\ link2q3' = TRUE
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q2,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ QuorumFor1(q1_owner, q1_epoch)
       /\ q1_owner = q2_owner /\ q1_epoch = q2_epoch
       /\ cert1_valid' = TRUE
       /\ cert1_owner' = q1_owner
       /\ cert1_epoch' = q1_epoch
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ QuorumFor1(q1_owner, q1_epoch)
       /\ q1_owner = q3_owner /\ q1_epoch = q3_epoch
       /\ cert1_valid' = TRUE
       /\ cert1_owner' = q1_owner
       /\ cert1_epoch' = q1_epoch
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ QuorumFor1(q2_owner, q2_epoch)
       /\ q2_owner = q3_owner /\ q2_epoch = q3_epoch
       /\ cert1_valid' = TRUE
       /\ cert1_owner' = q2_owner
       /\ cert1_epoch' = q2_epoch
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ cert1_valid' = FALSE
       /\ ~QuorumFor1(cert1_owner, cert1_epoch)
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ QuorumFor2(q1_owner, q1_epoch)
       /\ q1_owner = q2_owner /\ q1_epoch = q2_epoch
       /\ cert2_valid' = TRUE
       /\ cert2_owner' = q1_owner
       /\ cert2_epoch' = q1_epoch
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ QuorumFor2(q1_owner, q1_epoch)
       /\ q1_owner = q3_owner /\ q1_epoch = q3_epoch
       /\ cert2_valid' = TRUE
       /\ cert2_owner' = q1_owner
       /\ cert2_epoch' = q1_epoch
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ QuorumFor2(q2_owner, q2_epoch)
       /\ q2_owner = q3_owner /\ q2_epoch = q3_epoch
       /\ cert2_valid' = TRUE
       /\ cert2_owner' = q2_owner
       /\ cert2_epoch' = q2_epoch
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ cert2_valid' = FALSE
       /\ ~QuorumFor2(cert2_owner, cert2_epoch)
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ cert1_valid /\ cert1_owner = "none"
       /\ QuorumFor1("none", cert1_epoch)
       /\ link1q1 /\ q1_owner = "none" /\ q1_epoch = cert1_epoch
       /\ link1q2 /\ q2_owner = "none" /\ q2_epoch = cert1_epoch
       /\ q1_owner' = "r1" /\ q1_epoch' = cert1_epoch + 1
       /\ q2_owner' = "r1" /\ q2_epoch' = cert1_epoch + 1
       /\ cert1_valid' = TRUE /\ cert1_owner' = "r1" /\ cert1_epoch' = cert1_epoch + 1
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q3_owner, q3_epoch, cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ cert1_valid /\ cert1_owner = "none"
       /\ QuorumFor1("none", cert1_epoch)
       /\ link1q1 /\ q1_owner = "none" /\ q1_epoch = cert1_epoch
       /\ link1q3 /\ q3_owner = "none" /\ q3_epoch = cert1_epoch
       /\ q1_owner' = "r1" /\ q1_epoch' = cert1_epoch + 1
       /\ q3_owner' = "r1" /\ q3_epoch' = cert1_epoch + 1
       /\ cert1_valid' = TRUE /\ cert1_owner' = "r1" /\ cert1_epoch' = cert1_epoch + 1
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q2_owner, q2_epoch, cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ cert1_valid /\ cert1_owner = "none"
       /\ QuorumFor1("none", cert1_epoch)
       /\ link1q2 /\ q2_owner = "none" /\ q2_epoch = cert1_epoch
       /\ link1q3 /\ q3_owner = "none" /\ q3_epoch = cert1_epoch
       /\ q2_owner' = "r1" /\ q2_epoch' = cert1_epoch + 1
       /\ q3_owner' = "r1" /\ q3_epoch' = cert1_epoch + 1
       /\ cert1_valid' = TRUE /\ cert1_owner' = "r1" /\ cert1_epoch' = cert1_epoch + 1
       /\ result1' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q1_epoch, cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ cert2_valid /\ cert2_owner = "none"
       /\ QuorumFor2("none", cert2_epoch)
       /\ link2q1 /\ q1_owner = "none" /\ q1_epoch = cert2_epoch
       /\ link2q2 /\ q2_owner = "none" /\ q2_epoch = cert2_epoch
       /\ q1_owner' = "r2" /\ q1_epoch' = cert2_epoch + 1
       /\ q2_owner' = "r2" /\ q2_epoch' = cert2_epoch + 1
       /\ cert2_valid' = TRUE /\ cert2_owner' = "r2" /\ cert2_epoch' = cert2_epoch + 1
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q3_owner, q3_epoch, cert1_valid, cert1_owner, cert1_epoch,
                      effect_count, result1>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ cert2_valid /\ cert2_owner = "none"
       /\ QuorumFor2("none", cert2_epoch)
       /\ link2q1 /\ q1_owner = "none" /\ q1_epoch = cert2_epoch
       /\ link2q3 /\ q3_owner = "none" /\ q3_epoch = cert2_epoch
       /\ q1_owner' = "r2" /\ q1_epoch' = cert2_epoch + 1
       /\ q3_owner' = "r2" /\ q3_epoch' = cert2_epoch + 1
       /\ cert2_valid' = TRUE /\ cert2_owner' = "r2" /\ cert2_epoch' = cert2_epoch + 1
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q2_owner, q2_epoch, cert1_valid, cert1_owner, cert1_epoch,
                      effect_count, result1>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ cert2_valid /\ cert2_owner = "none"
       /\ QuorumFor2("none", cert2_epoch)
       /\ link2q2 /\ q2_owner = "none" /\ q2_epoch = cert2_epoch
       /\ link2q3 /\ q3_owner = "none" /\ q3_epoch = cert2_epoch
       /\ q2_owner' = "r2" /\ q2_epoch' = cert2_epoch + 1
       /\ q3_owner' = "r2" /\ q3_epoch' = cert2_epoch + 1
       /\ cert2_valid' = TRUE /\ cert2_owner' = "r2" /\ cert2_epoch' = cert2_epoch + 1
       /\ result2' = "claimed"
       /\ UNCHANGED <<ready1, ready2, link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q1_epoch, cert1_valid, cert1_owner, cert1_epoch,
                      effect_count, result1>>
    \/ /\ Active
       /\ result1 = "ready"
       /\ (~cert1_valid \/ cert1_owner # "none" \/ ~QuorumFor1("none", cert1_epoch))
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ result2 = "ready"
       /\ (~cert2_valid \/ cert2_owner # "none" \/ ~QuorumFor2("none", cert2_epoch))
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ cert1_valid /\ cert1_owner = "r1"
       /\ QuorumFor1("r1", cert1_epoch)
       /\ effect_count = 0
       /\ result1' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ cert2_valid /\ cert2_owner = "r2"
       /\ QuorumFor2("r2", cert2_epoch)
       /\ effect_count = 0
       /\ result2' = "executed"
       /\ effect_count' = 1
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      result1>>
    \/ /\ Active
       /\ result1 = "claimed"
       /\ (~cert1_valid \/ cert1_owner # "r1" \/ ~QuorumFor1("r1", cert1_epoch))
       /\ result1' = "rejected"
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result2>>
    \/ /\ Active
       /\ result2 = "claimed"
       /\ (~cert2_valid \/ cert2_owner # "r2" \/ ~QuorumFor2("r2", cert2_epoch))
       /\ result2' = "rejected"
       /\ UNCHANGED <<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1>>
    \/ /\ UNCHANGED <<ready1, ready2,
                     link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                     q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                     cert1_valid, cert1_owner, cert1_epoch,
                     cert2_valid, cert2_owner, cert2_epoch,
                     effect_count, result1, result2>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvExecutedRequiresCurrentQuorum ==
    /\ (result1 = "executed" => /\ cert1_valid /\ cert1_owner = "r1" /\ QuorumFor1("r1", cert1_epoch))
    /\ (result2 = "executed" => /\ cert2_valid /\ cert2_owner = "r2" /\ QuorumFor2("r2", cert2_epoch))

InvStoreOwnersWellFormed ==
    /\ q1_owner \in Owners
    /\ q2_owner \in Owners
    /\ q3_owner \in Owners

InvNoDualClaimOrExecution ==
    ~((result1 \in {"claimed", "executed"}) /\ (result2 \in {"claimed", "executed"}))

InvNoDualExecution ==
    ~((result1 = "executed") /\ (result2 = "executed"))

Spec ==
    Init /\ [][Next]_<<ready1, ready2,
                      link1q1, link1q2, link1q3, link2q1, link2q2, link2q3,
                      q1_owner, q2_owner, q3_owner, q1_epoch, q2_epoch, q3_epoch,
                      cert1_valid, cert1_owner, cert1_epoch,
                      cert2_valid, cert2_owner, cert2_epoch,
                      effect_count, result1, result2>>

====
