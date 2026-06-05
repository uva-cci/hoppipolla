% A policy that adds a soft constraint which prioritizes nodes with higher
% average device PSF.
%
% Nodes without PSF data receive an explicit default of 0 via the
% has_metadata/2 coverage atoms, so the treatment of unknown coverage is
% visible in the policy instead of being an artifact of closed-world
% aggregation. The aggregate elements include the AS so that two nodes
% with the same PSF value are summed, not collapsed by set semantics.

known_psf(AS, AvgPsf) :- avg_psf(AS, AvgPsf).
known_psf(AS, 0) :- chosen(AS, _, _, _), not has_metadata("avg_psf", AS).

total_avg_psf(TotAvgPsf) :-
    TotAvgPsf = #sum{ AvgPsf, AS : known_psf(AS, AvgPsf), chosen(AS, _, _, _) }.

#maximize { TotAvgPsf : total_avg_psf(TotAvgPsf) }.
