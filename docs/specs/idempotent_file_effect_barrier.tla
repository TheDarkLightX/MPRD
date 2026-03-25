---- MODULE idempotent_file_effect_barrier ----
EXTENDS Naturals

WriterStates == {"idle", "ready", "committed"}

\* Intentionally narrow abstraction:
\* - one concrete effect id and one local idempotent-file sink
\* - writing the per-nonce file is the side effect and the durable barrier
\* - the filesystem create is modeled as atomic for this local sink
\* - once the file exists, later writers short-circuit idempotently instead of
\*   creating a second effect
\* - no liveness claims, no partial filesystem corruption, and no replicated fs
VARIABLES writer_a, writer_b, file_present, effect_count

Init ==
    /\ writer_a = "idle"
    /\ writer_b = "idle"
    /\ file_present = FALSE
    /\ effect_count = 0

Next ==
    \/ /\ writer_a = "idle"
       /\ writer_a' = "ready"
       /\ UNCHANGED <<writer_b, file_present, effect_count>>
    \/ /\ writer_b = "idle"
       /\ writer_b' = "ready"
       /\ UNCHANGED <<writer_a, file_present, effect_count>>
    \/ /\ writer_a = "ready"
       /\ ~file_present
       /\ effect_count = 0
       /\ writer_a' = "committed"
       /\ file_present' = TRUE
       /\ effect_count' = 1
       /\ UNCHANGED <<writer_b>>
    \/ /\ writer_b = "ready"
       /\ ~file_present
       /\ effect_count = 0
       /\ writer_b' = "committed"
       /\ file_present' = TRUE
       /\ effect_count' = 1
       /\ UNCHANGED <<writer_a>>
    \/ /\ writer_a = "ready"
       /\ file_present
       /\ writer_a' = "committed"
       /\ UNCHANGED <<writer_b, file_present, effect_count>>
    \/ /\ writer_b = "ready"
       /\ file_present
       /\ writer_b' = "committed"
       /\ UNCHANGED <<writer_a, file_present, effect_count>>
    \/ /\ UNCHANGED <<writer_a, writer_b, file_present, effect_count>>

InvAtMostOnceEffect ==
    effect_count <= 1

InvFilePresentImpliesEffect ==
    file_present => effect_count = 1

InvWriterACommittedRequiresBarrier ==
    writer_a = "committed" => file_present /\ effect_count = 1

InvWriterBCommittedRequiresBarrier ==
    writer_b = "committed" => file_present /\ effect_count = 1

InvWellFormed ==
    /\ writer_a \in WriterStates
    /\ writer_b \in WriterStates

Spec ==
    Init /\ [][Next]_<<writer_a, writer_b, file_present, effect_count>>

====
