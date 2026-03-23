---- MODULE serial_commit_network_barrier ----
EXTENDS Naturals, Sequences

Results == {"pending", "committed", "rejected"}
CheckpointStates == {"fresh", "stale", "withheld"}

VARIABLES eval_done, cache_done, checkpoint_state, quorum_ok, tau_api_up,
          registry_fresh, replay_clear, selector_bound, source_bound,
          private_mode, mode_c_key_allowed, result

LocalReady ==
    /\ eval_done
    /\ cache_done
    /\ replay_clear
    /\ selector_bound
    /\ source_bound
    /\ (~private_mode \/ mode_c_key_allowed)

NetworkReady ==
    /\ checkpoint_state = "fresh"
    /\ quorum_ok
    /\ tau_api_up
    /\ registry_fresh

CommitReady ==
    /\ LocalReady
    /\ NetworkReady

Init ==
    /\ eval_done = FALSE
    /\ cache_done = FALSE
    /\ checkpoint_state = "stale"
    /\ quorum_ok = TRUE
    /\ tau_api_up = TRUE
    /\ registry_fresh = FALSE
    /\ replay_clear = FALSE
    /\ selector_bound = FALSE
    /\ source_bound = FALSE
    /\ private_mode = FALSE
    /\ mode_c_key_allowed = FALSE
    /\ result = "pending"

Next ==
    \/ /\ ~eval_done
       /\ result = "pending"
       /\ eval_done' = TRUE
       /\ UNCHANGED <<cache_done, checkpoint_state, quorum_ok, tau_api_up,
                      registry_fresh, replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ ~cache_done
       /\ result = "pending"
       /\ cache_done' = TRUE
       /\ UNCHANGED <<eval_done, checkpoint_state, quorum_ok, tau_api_up,
                      registry_fresh, replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ checkpoint_state # "fresh"
       /\ result = "pending"
       /\ checkpoint_state' = "fresh"
       /\ UNCHANGED <<eval_done, cache_done, quorum_ok, tau_api_up,
                      registry_fresh, replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ checkpoint_state # "stale"
       /\ result = "pending"
       /\ checkpoint_state' = "stale"
       /\ registry_fresh' = FALSE
       /\ UNCHANGED <<eval_done, cache_done, quorum_ok, tau_api_up,
                      replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ checkpoint_state # "withheld"
       /\ result = "pending"
       /\ checkpoint_state' = "withheld"
       /\ registry_fresh' = FALSE
       /\ UNCHANGED <<eval_done, cache_done, quorum_ok, tau_api_up,
                      replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ quorum_ok
       /\ result = "pending"
       /\ quorum_ok' = FALSE
       /\ registry_fresh' = FALSE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, tau_api_up,
                      replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ ~quorum_ok
       /\ result = "pending"
       /\ quorum_ok' = TRUE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, tau_api_up,
                      registry_fresh, replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ tau_api_up
       /\ result = "pending"
       /\ tau_api_up' = FALSE
       /\ registry_fresh' = FALSE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ ~tau_api_up
       /\ result = "pending"
       /\ tau_api_up' = TRUE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      registry_fresh, replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ checkpoint_state = "fresh"
       /\ quorum_ok
       /\ tau_api_up
       /\ ~registry_fresh
       /\ result = "pending"
       /\ registry_fresh' = TRUE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, replay_clear, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ ~replay_clear
       /\ result = "pending"
       /\ replay_clear' = TRUE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, selector_bound, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ ~selector_bound
       /\ result = "pending"
       /\ selector_bound' = TRUE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, replay_clear, source_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ ~source_bound
       /\ result = "pending"
       /\ source_bound' = TRUE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, replay_clear, selector_bound,
                      private_mode, mode_c_key_allowed, result>>
    \/ /\ ~private_mode
       /\ result = "pending"
       /\ private_mode' = TRUE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, replay_clear, selector_bound,
                      source_bound, mode_c_key_allowed, result>>
    \/ /\ private_mode
       /\ ~mode_c_key_allowed
       /\ result = "pending"
       /\ mode_c_key_allowed' = TRUE
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, replay_clear, selector_bound,
                      source_bound, private_mode, result>>
    \/ /\ CommitReady
       /\ result = "pending"
       /\ result' = "committed"
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, replay_clear, selector_bound,
                      source_bound, private_mode, mode_c_key_allowed>>
    \/ /\ LocalReady
       /\ ~NetworkReady
       /\ result = "pending"
       /\ result' = "rejected"
       /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, replay_clear, selector_bound,
                      source_bound, private_mode, mode_c_key_allowed>>
    \/ /\ UNCHANGED <<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, replay_clear, selector_bound,
                      source_bound, private_mode, mode_c_key_allowed, result>>

InvCommittedRequiresNetworkReady ==
    result = "committed" => NetworkReady

InvCommittedRequiresLocalReady ==
    result = "committed" => LocalReady

InvPrivateCommitRequiresModeCKey ==
    (result = "committed" /\ private_mode) => mode_c_key_allowed

InvRejectedLocalReadyImpliesNetworkFault ==
    (result = "rejected" /\ LocalReady) => ~NetworkReady

Spec ==
    Init /\ [][Next]_<<eval_done, cache_done, checkpoint_state, quorum_ok,
                      tau_api_up, registry_fresh, replay_clear, selector_bound,
                      source_bound, private_mode, mode_c_key_allowed, result>>

====
