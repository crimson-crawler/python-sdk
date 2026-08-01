"""Default ``include=[...]`` presets for the Crimson Crawler enrichment endpoints.

The API's ``include`` parameter controls which enrichment layers run on a request.
Picking the right combination per use-case is part of the API's contract — these
constants encode the most common shapes so consumers do not have to memorize them.

Use them via the convenience methods on :class:`CrawlerClient`, or pass them
directly to the generated endpoint helpers when calling raw.
"""

from __future__ import annotations

from typing import Final

CVE_FULL_WALK: Final[list[str]] = [
    "details",
    "epss",
    "kev",
    "cwe",
    "capec",
    "techniques",
    "tie",
    "misp",
    "knowledgebase",
    "web",
]
"""Full CVE → CWE → CAPEC → ATT&CK → TIE chain plus MISP, knowledge base, and web context.

This is the recon-agent default. Returns the complete enrichment surface in
one round trip. Latency is the highest of any preset (~5-30s on cold cache,
sub-second on warm cache).
"""

CVE_FAST: Final[list[str]] = ["details", "epss", "kev"]
"""Quick CVE artifact-enrichment — score, exploit probability, KEV status. No chain walk."""

CVE_NARRATIVE: Final[list[str]] = [*CVE_FULL_WALK, "summary", "groups", "campaigns"]
"""Full walk plus AI summary and adversary attribution. Use for report generation."""

IOC_FULL_WALK: Final[list[str]] = [
    "misp_attributes",
    "techniques",
    "groups",
    "knowledgebase",
    "web",
]
"""IOC → MISP → linked techniques → groups, plus knowledge base and web."""

IOC_FAST: Final[list[str]] = ["misp_attributes"]
"""IOC lookup against MISP feeds only — no technique resolution."""

CWE_FULL_WALK: Final[list[str]] = ["capecs", "techniques", "tie"]
"""CWE → CAPEC → ATT&CK with TIE predictions. Use when starting from a weakness."""

TECHNIQUE_FULL: Final[list[str]] = [
    "details",
    "tie",
    "groups",
    "software",
    "campaigns",
    "navigator",
]
"""Technique enrichment with TIE, adversary attribution, and Navigator JSON."""

PRODUCT_FULL: Final[list[str]] = [
    "details",
    "epss",
    "kev",
    "cwe",
    "capec",
    "techniques",
    "tie",
    "misp",
    "knowledgebase",
    "web",
]
"""Full product/version walk: matched CVEs with severity, exploit signals, weakness mapping,
ATT&CK techniques, threat predictions, MISP events, knowledge base, and web context."""

PACKAGE_FULL: Final[list[str]] = [
    "details",
    "severity",
    "affected",
    "references",
    "epss",
    "kev",
    "cwe",
    "capec",
    "techniques",
    "tie",
]
"""Full open-source-package walk: OSV.dev advisories (severity, affected/fixed ranges, references)
plus each aliased CVE enriched through the CWE → CAPEC → ATT&CK + EPSS/KEV chain. The package-
ecosystem analogue of :data:`PRODUCT_FULL`."""

CAPEC_FULL: Final[list[str]] = [
    "details",
    "techniques",
    "tie",
    "cves",
    "groups",
    "software",
    "campaigns",
    "navigator",
]
"""CAPEC → ATT&CK walk with TIE predictions, the CVEs exploiting the pattern, and adversary
attribution (groups, software, campaigns) plus a Navigator layer. The attack-pattern analogue of
:data:`CWE_FULL_WALK`, which stops at the technique hop."""

ATLAS_FULL: Final[list[str]] = [
    "details",
    "techniques",
    "tie",
    "groups",
    "software",
    "campaigns",
    "navigator",
]
"""Adversarial-ML (ATLAS) technique walk: mapped ATT&CK techniques with TIE predictions, adversary
attribution, and Navigator JSON. Shaped like :data:`TECHNIQUE_FULL` with the ATLAS → ATT&CK hop
added."""

DISARM_FULL: Final[list[str]] = [
    "details",
    "countermeasures",
    "techniques",
    "tie",
    "groups",
    "software",
    "campaigns",
    "navigator",
]
"""Disinformation (DISARM) technique walk with its countermeasures, mapped ATT&CK techniques, TIE
predictions, and adversary attribution. DISARM has no CVE or NIST-control layer, so the chain ends
at attribution."""

DEFEND_FULL: Final[list[str]] = ["details", "techniques", "knowledgebase", "web"]
"""D3FEND defensive-technique walk: the countered ATT&CK techniques plus knowledge base and web
context. D3FEND exposes no attribution or CVE layers — these four are its whole surface."""

GROUP_FULL: Final[list[str]] = [
    "details",
    "techniques",
    "software",
    "tie",
    "campaigns",
    "cves",
    "sectors",
    "locations",
    "navigator",
]
"""Threat-actor walk: the group's techniques and tooling with TIE predictions, its campaigns and
exploited CVEs, the sectors and regions it targets, and a Navigator layer."""

SOFTWARE_FULL: Final[list[str]] = [
    "details",
    "techniques",
    "tie",
    "groups",
    "campaigns",
    "cves",
    "navigator",
]
"""Malware/tool walk: the techniques the software implements with TIE predictions, the groups and
campaigns wielding it, the CVEs it exploits, and a Navigator layer."""

CAMPAIGN_FULL: Final[list[str]] = [
    "details",
    "techniques",
    "tie",
    "groups",
    "software",
    "cves",
    "navigator",
]
"""Campaign walk: techniques used with TIE predictions, attributed groups, tooling, exploited CVEs,
and a Navigator layer."""

LOCATION_FULL: Final[list[str]] = [
    "details",
    "groups",
    "techniques",
    "tie",
    "software",
    "campaigns",
    "sectors",
    "navigator",
]
"""Regional threat-landscape walk: groups active in the region, their techniques with TIE
predictions, tooling, campaigns, the sectors they hit, and a Navigator layer."""

SECTOR_FULL: Final[list[str]] = [
    "details",
    "groups",
    "techniques",
    "tie",
    "software",
    "campaigns",
    "locations",
    "navigator",
]
"""Industry-sector threat-landscape walk: the mirror of :data:`LOCATION_FULL` — groups targeting the
sector, their techniques with TIE predictions, tooling, campaigns, the regions involved, and a
Navigator layer."""

__all__ = [
    "ATLAS_FULL",
    "CAMPAIGN_FULL",
    "CAPEC_FULL",
    "CVE_FAST",
    "CVE_FULL_WALK",
    "CVE_NARRATIVE",
    "CWE_FULL_WALK",
    "DEFEND_FULL",
    "DISARM_FULL",
    "GROUP_FULL",
    "IOC_FAST",
    "IOC_FULL_WALK",
    "LOCATION_FULL",
    "PACKAGE_FULL",
    "PRODUCT_FULL",
    "SECTOR_FULL",
    "SOFTWARE_FULL",
    "TECHNIQUE_FULL",
]
