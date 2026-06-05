% select exactly one of the candidate paths provided by the network stack;
% chains are valid by construction, so no continuity or reachability
% constraints are needed and fabricated (spliced) paths are unrepresentable
{ chosen_path(P) : path(P) } = 1.

% derive the link-level view used by policies, preserving the original
% chosen/4 and link/4 policy language
chosen(X, XIF, Y, YIF) :- chosen_path(P), in_path(P, X, XIF, Y, YIF).
link(X, XIF, Y, YIF) :- in_path(_, X, XIF, Y, YIF).

#show chosen_path/1.
