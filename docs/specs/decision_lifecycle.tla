---- MODULE decision_lifecycle ----
EXTENDS Naturals, Sequences

CONSTANTS Allowed, Denied

(\* Status domains \*)
ProofStatuses == {"pending", "verified", "failed"}
ExecStatuses == {"skipped", "success", "failed"}

VARIABLES proof, exec, verdict

Init ==
    /\ proof = "pending"
    /\ exec = "skipped"
    /\ verdict \in {Allowed, Denied}

ProofNext ==
    \/ /\ proof = "pending"
       /\ proof' \in {"pending", "verified", "failed"}
    \/ /\ proof = "verified"
       /\ proof' = "verified"
    \/ /\ proof = "failed"
       /\ proof' = "failed"

ExecNext ==
    \/ /\ exec = "skipped"
       /\ verdict = Allowed
       /\ proof = "verified"
       /\ exec' \in {"success", "failed"}
    \/ /\ exec = "success"
       /\ exec' = "success"
    \/ /\ exec = "failed"
       /\ exec' = "failed"
    \/ /\ exec = "skipped"
       /\ exec' = "skipped"

Next ==
    \/ /\ ProofNext
       /\ UNCHANGED <<exec, verdict>>
    \/ /\ ExecNext
       /\ UNCHANGED <<proof, verdict>>
    \/ /\ UNCHANGED <<proof, exec, verdict>>

InvDeniedImpliesSkipped == verdict = Denied => exec = "skipped"
InvExecRequiresVerified == exec \in {"success", "failed"} => proof = "verified"

Spec == Init /\ [][Next]_<<proof, exec, verdict>>

THEOREM Spec => []InvDeniedImpliesSkipped
THEOREM Spec => []InvExecRequiresVerified

====
