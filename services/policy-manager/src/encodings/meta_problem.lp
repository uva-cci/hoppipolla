conflicting(P2, P1) :- conflicting(P1, P2).

:- conflicting(P1, P2),
    not overrides(_, P2),
    not overrides(_, P1).

deactivate(P) :- overrides(_, P).

% filter out empty models
:- #count { : deactivate(_) } == 0, #count { : conflicting(_, _) } > 0.

#show deactivate/1.
