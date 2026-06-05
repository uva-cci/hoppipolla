% A policy that denies all ASes with border routers operating outside of the
% GDPR regulated area.
%
% Missing metadata is handled explicitly: under ASP's closed-world semantics
% a node with no geolocation data would otherwise be indistinguishable from
% a non-compliant one. The has_metadata/2 coverage atoms emitted by the
% policy manager make the fail-closed behavior a deliberate, separate rule.

gdprArea("AT").  % Austria
gdprArea("BE").  % Belgium
gdprArea("BG").  % Bulgaria
gdprArea("HR").  % Croatia
gdprArea("CY").  % Cyprus
gdprArea("CZ").  % Czechia
gdprArea("DK").  % Denmark
gdprArea("EE").  % Estonia
gdprArea("FI").  % Finland
gdprArea("FR").  % France
gdprArea("DE").  % Germany
gdprArea("GR").  % Greece
gdprArea("HU").  % Hungary
gdprArea("IS").  % Iceland
gdprArea("IE").  % Ireland
gdprArea("IT").  % Italy
gdprArea("LV").  % Latvia
gdprArea("LI").  % Liechtenstein
gdprArea("LT").  % Lithuania
gdprArea("LU").  % Luxembourg
gdprArea("MT").  % Malta
gdprArea("NL").  % Netherlands
gdprArea("NO").  % Norway
gdprArea("PL").  % Poland
gdprArea("PT").  % Portugal
gdprArea("RO").  % Romania
gdprArea("SK").  % Slovakia
gdprArea("SI").  % Slovenia
gdprArea("ES").  % Spain
gdprArea("SE").  % Sweden

% deny nodes known to operate anywhere outside the GDPR area
:- chosen(AS, _, _, _), operates(AS, Country), not gdprArea(Country).

% deny nodes with no geolocation coverage at all (explicit fail-closed)
:- chosen(AS, _, _, _), not has_metadata("operates", AS).
