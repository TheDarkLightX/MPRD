---- MODULE idempotent_http_effect_barrier ----
EXTENDS Naturals

InitiatorStates == {"idle", "ready", "pending", "effect_emitted", "committed"}
RetryStates == {"idle", "ready", "committed", "rejected"}

\* Intentionally narrow abstraction:
\* - one concrete effect id and one local barrier journal
\* - the initiator writes a local pending marker before remote execution
\* - the remote endpoint may accept the effect before the local process can
\*   promote the barrier to committed
\* - retries must not emit a second remote effect while a pending marker
\*   remains unresolved; they reject fail-closed instead
\* - once the committed marker exists, retries short-circuit idempotently
\* - no liveness claims, no manual recovery protocol, and no replicated journal
VARIABLES initiator, retry, executor_up,
          pending_barrier, committed_barrier, effect_count

Init ==
    /\ initiator = "idle"
    /\ retry = "idle"
    /\ executor_up = TRUE
    /\ pending_barrier = FALSE
    /\ committed_barrier = FALSE
    /\ effect_count = 0

Next ==
    \/ /\ initiator = "idle"
       /\ initiator' = "ready"
       /\ UNCHANGED <<retry, executor_up, pending_barrier,
                      committed_barrier, effect_count>>
    \/ /\ retry = "idle"
       /\ retry' = "ready"
       /\ UNCHANGED <<initiator, executor_up, pending_barrier,
                      committed_barrier, effect_count>>
    \/ /\ initiator = "ready"
       /\ executor_up
       /\ ~pending_barrier
       /\ ~committed_barrier
       /\ initiator' = "pending"
       /\ pending_barrier' = TRUE
       /\ UNCHANGED <<retry, executor_up, committed_barrier, effect_count>>
    \/ /\ initiator = "pending"
       /\ executor_up
       /\ pending_barrier
       /\ ~committed_barrier
       /\ effect_count = 0
       /\ initiator' = "effect_emitted"
       /\ effect_count' = 1
       /\ UNCHANGED <<retry, executor_up, pending_barrier, committed_barrier>>
    \/ /\ initiator = "effect_emitted"
       /\ executor_up
       /\ pending_barrier
       /\ ~committed_barrier
       /\ initiator' = "committed"
       /\ pending_barrier' = FALSE
       /\ committed_barrier' = TRUE
       /\ UNCHANGED <<retry, executor_up, effect_count>>
    \/ /\ initiator = "effect_emitted"
       /\ executor_up
       /\ pending_barrier
       /\ ~committed_barrier
       /\ executor_up' = FALSE
       /\ UNCHANGED <<initiator, retry, pending_barrier,
                      committed_barrier, effect_count>>
    \/ /\ ~executor_up
       /\ executor_up' = TRUE
       /\ UNCHANGED <<initiator, retry, pending_barrier,
                      committed_barrier, effect_count>>
    \/ /\ retry = "ready"
       /\ committed_barrier
       /\ retry' = "committed"
       /\ UNCHANGED <<initiator, executor_up, pending_barrier,
                      committed_barrier, effect_count>>
    \/ /\ retry = "ready"
       /\ pending_barrier
       /\ ~committed_barrier
       /\ retry' = "rejected"
       /\ UNCHANGED <<initiator, executor_up, pending_barrier,
                      committed_barrier, effect_count>>
    \/ /\ UNCHANGED <<initiator, retry, executor_up,
                      pending_barrier, committed_barrier, effect_count>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvCommittedBarrierImpliesEffect ==
    committed_barrier => effect_count = 1

InvCommittedBarrierClearsPending ==
    committed_barrier => ~pending_barrier

InvRetryCommittedRequiresCommittedBarrier ==
    retry = "committed" => committed_barrier /\ effect_count = 1

InvRetryRejectedFollowsBarrierRisk ==
    retry = "rejected" => pending_barrier \/ effect_count = 1

InvRemoteUncertaintyKeepsPending ==
    initiator = "effect_emitted" => pending_barrier /\ ~committed_barrier /\ effect_count = 1

InvWellFormed ==
    /\ initiator \in InitiatorStates
    /\ retry \in RetryStates

Spec ==
    Init /\ [][Next]_<<initiator, retry, executor_up,
                      pending_barrier, committed_barrier, effect_count>>

====
