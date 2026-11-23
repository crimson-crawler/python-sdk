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
    "android_bulletin",
    "capec",
    "cellular",
    "certfr_advisories",
    "cisa_campaigns",
    "cisa_kev",
    "csaf_advisories",
    "cvss_bt",
    "cwe",
    "details",
    "detections",
    "emb3d",
    "epss",
    "exploits",
    "kev",
    "log_sources",
    "mitigations",
    "nist_controls",
    "ot_context",
    "poc",
    "sigma",
    "osv",
    "ssvc",
    "techniques",
    "tie",
    "weakness_ranks",
]
"""The API's default for `/enrich/cve`: every seeded or committed layer.

Mirrors the server's Tier A set, so a caller drilling into the raw endpoint gets
the same answer. Pass ``include`` to narrow it. Cold cache is a few seconds, warm
is sub-second.
"""

CVE_FAST: Final[list[str]] = ["details", "epss", "kev", "cisa_kev"]
"""Quick CVE artifact-enrichment — score, exploit probability, KEV status. No chain walk."""

CVE_NARRATIVE: Final[list[str]] = [*CVE_FULL_WALK, "summary", "groups", "campaigns"]
"""Full walk plus AI summary and adversary attribution. Use for report generation."""

IOC_FULL_WALK: Final[list[str]] = [
    "cisa_campaigns",
    "defend",
    "detections",
    "galaxies",
    "listed_on",
    "log_sources",
    "misp_attributes",
    "mitigations",
    "network_context",
    "nist_controls",
    "sightings",
    "techniques",
    "tie",
    "warninglist",
]
"""The API's default for `/enrich/ioc`: MISP attributes, galaxies, and the technique layers."""

IOC_FAST: Final[list[str]] = ["misp_attributes"]
"""IOC lookup against MISP feeds only — no technique resolution."""

CWE_FULL_WALK: Final[list[str]] = ["capecs", "techniques", "tie"]
"""CWE → CAPEC → ATT&CK with TIE predictions. Use when starting from a weakness."""

TECHNIQUE_FULL: Final[list[str]] = [
    "asset_classes",
    "atomic_red_team",
    "cisa_campaigns",
    "defend",
    "details",
    "detections",
    "fight",
    "framework_mappings",
    "fraud",
    "log_sources",
    "lolbas",
    "lotl",
    "mitigations",
    "nist_controls",
    "sigma",
    "tie",
]
"""Technique enrichment with TIE, adversary attribution, and Navigator JSON."""

PRODUCT_FULL: Final[list[str]] = [
    "android_bulletin",
    "capec",
    "cellular",
    "certfr_advisories",
    "cisa_campaigns",
    "cisa_kev",
    "csaf_advisories",
    "cvss_bt",
    "cwe",
    "defend",
    "details",
    "detections",
    "emb3d",
    "epss",
    "exploits",
    "kev",
    "log_sources",
    "mitigations",
    "nist_controls",
    "ot_context",
    "osv",
    "poc",
    "risk_summary",
    "sigma",
    "ssvc",
    "techniques",
    "tie",
    "misp",
    "knowledgebase",
    "weakness_ranks",
]
"""Product layers plus MISP and knowledge-base context; wrapper defaults to 2 CVEs per page."""

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
]
"""Adversarial-ML (ATLAS) technique walk: the technique plus its ATLAS parent/sub-technique
family. ATLAS carries no ATLAS-to-Enterprise edge, so there is no Enterprise-keyed layer
(predictions / adversary graph / Navigator / CVEs / NIST controls) to walk."""

DISARM_FULL: Final[list[str]] = [
    "details",
    "techniques",
]
"""Disinformation (DISARM) technique walk: the technique plus its DISARM parent/sub-technique
family. DISARM has no ATT&CK-Enterprise-keyed layer to walk — the corpus carries no
groups/software/campaigns/mitigations/detections/defend objects, and Navigator renders
enterprise/mobile/ICS ATT&CK layers only."""

F3_FULL: Final[list[str]] = [
    "details",
    "techniques",
    "knowledgebase",
]
"""Fraud-technique (MITRE F3) walk: the F3 object plus the ATT&CK Enterprise techniques its 43
borrowed ``T####`` ids resolve to, with knowledge base context. F3 carries no adversary
graph or attribution layer, so the chain ends at the technique hop."""

CLOAK_FULL: Final[list[str]] = [
    "details",
    "knowledgebase",
]
"""Concealment-technique (CLOAK) walk: the CLOAK object plus knowledge base context. CLOAK
objects carry no ATT&CK references at all, so there is no technique hop — no ``techniques``, no TIE
predictions, and no adversary attribution."""

DEFEND_FULL: Final[list[str]] = ["details", "techniques", "knowledgebase"]
"""D3FEND defensive-technique walk: the countered ATT&CK techniques plus knowledge base
context. D3FEND exposes no attribution or CVE layers — these three are its whole walk; the KB
revision history (`versions`) is opt-in on every endpoint, not part of any preset."""

GROUP_FULL: Final[list[str]] = [
    "details",
    "detections",
    "log_sources",
    "mitigations",
    "nist_controls",
    "techniques",
    "software",
    "tie",
    "campaigns",
    "cves",
    "navigator",
]
"""Threat-actor walk: the group's techniques and tooling with TIE predictions, its campaigns and
exploited CVEs, and a Navigator layer."""

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
    "knowledgebase",
]
"""Regional profile walk: the location's own metadata plus knowledge base context."""

SECTOR_FULL: Final[list[str]] = [
    "details",
    "knowledgebase",
]
"""Industry-sector profile walk: the sector's own metadata plus knowledge base context."""

__all__ = [
    "ATLAS_FULL",
    "CAMPAIGN_FULL",
    "CAPEC_FULL",
    "CLOAK_FULL",
    "CVE_FAST",
    "CVE_FULL_WALK",
    "CVE_NARRATIVE",
    "CWE_FULL_WALK",
    "DEFEND_FULL",
    "DISARM_FULL",
    "F3_FULL",
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
