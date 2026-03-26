---- MODULE idempotent_http_startup_pending_barrier ----
EXTENDS Naturals

ServerStates == {"down", "blocked_pending", "serving"}
RetryStates == {"idle", "ready", "committed", "rejected"}

\* Intentionally narrow abstraction:
\* - one local HTTP effect journal survives process restart
\* - a previous run may leave a pending barrier behind after an uncertain remote
\*   outcome, with the remote effect count still unknown to the new process
\* - production startup must fail closed on that unresolved pending barrier
\*   instead of quietly entering serving state
\* - once the pending barrier is explicitly resolved (clear if no effect, or
\*   committed if an effect is known durable), startup may proceed
\* - retries short-circuit on committed or reject on pending; no liveness or
\*   remote reconciliation protocol is claimed here
VARIABLES server, retry, pending_barrier, committed_barrier, effect_count

Init ==
    /\ server = "down"
    /\ retry = "idle"
    /\ pending_barrier = FALSE
    /\ committed_barrier = FALSE
    /\ effect_count = 0

Next ==
    \/ /\ retry = "idle"
       /\ retry' = "ready"
       /\ UNCHANGED <<server, pending_barrier, committed_barrier, effect_count>>
    \/ /\ server = "down"
       /\ ~pending_barrier
       /\ ~committed_barrier
       /\ effect_count = 0
       /\ pending_barrier' = TRUE
       /\ UNCHANGED <<server, retry, committed_barrier, effect_count>>
    \/ /\ server = "down"
       /\ ~pending_barrier
       /\ ~committed_barrier
       /\ effect_count = 0
       /\ pending_barrier' = TRUE
       /\ effect_count' = 1
       /\ UNCHANGED <<server, retry, committed_barrier>>
    \/ /\ server = "down"
       /\ pending_barrier
       /\ ~committed_barrier
       /\ server' = "blocked_pending"
       /\ UNCHANGED <<retry, pending_barrier, committed_barrier, effect_count>>
    \/ /\ server = "down"
       /\ ~pending_barrier
       /\ server' = "serving"
       /\ UNCHANGED <<retry, pending_barrier, committed_barrier, effect_count>>
    \/ /\ server = "blocked_pending"
       /\ pending_barrier
       /\ ~committed_barrier
       /\ effect_count = 0
       /\ pending_barrier' = FALSE
       /\ server' = "down"
       /\ UNCHANGED <<retry, committed_barrier, effect_count>>
    \/ /\ server = "blocked_pending"
       /\ pending_barrier
       /\ ~committed_barrier
       /\ effect_count = 1
       /\ pending_barrier' = FALSE
       /\ committed_barrier' = TRUE
       /\ server' = "down"
       /\ UNCHANGED <<retry, effect_count>>
    \/ /\ retry = "ready"
       /\ pending_barrier
       /\ ~committed_barrier
       /\ retry' = "rejected"
       /\ UNCHANGED <<server, pending_barrier, committed_barrier, effect_count>>
    \/ /\ retry = "ready"
       /\ committed_barrier
       /\ retry' = "committed"
       /\ UNCHANGED <<server, pending_barrier, committed_barrier, effect_count>>
    \/ /\ UNCHANGED <<server, retry, pending_barrier, committed_barrier, effect_count>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvCommittedBarrierImpliesEffect ==
    committed_barrier => effect_count = 1

InvServingRequiresNoPendingBarrier ==
    server = "serving" => ~pending_barrier

InvBlockedPendingRequiresPendingBarrier ==
    server = "blocked_pending" => pending_barrier /\ ~committed_barrier

InvRetryCommittedRequiresCommittedBarrier ==
    retry = "committed" => committed_barrier /\ effect_count = 1

InvWellFormed ==
    /\ server \in ServerStates
    /\ retry \in RetryStates

Spec ==
    Init /\ [][Next]_<<server, retry, pending_barrier, committed_barrier, effect_count>>

====
