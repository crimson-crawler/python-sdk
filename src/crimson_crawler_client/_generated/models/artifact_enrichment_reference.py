from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.artifact_enrichment_reference_action_type_0 import ArtifactEnrichmentReferenceActionType0
from ..models.artifact_enrichment_reference_confidence_type_0 import ArtifactEnrichmentReferenceConfidenceType0
from ..models.artifact_enrichment_reference_exploit_maturity_type_0 import (
    ArtifactEnrichmentReferenceExploitMaturityType0,
)
from ..models.artifact_enrichment_reference_likelihood_type_0 import ArtifactEnrichmentReferenceLikelihoodType0
from ..models.artifact_enrichment_reference_techniques_provenance_type_0 import (
    ArtifactEnrichmentReferenceTechniquesProvenanceType0,
)
from ..models.artifact_enrichment_reference_type import ArtifactEnrichmentReferenceType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.activity_summary import ActivitySummary
    from ..models.admiralty_grade import AdmiraltyGrade
    from ..models.affected_configuration import AffectedConfiguration
    from ..models.android_bulletin import AndroidBulletin
    from ..models.artifact_enrichment_reference_distro_advisories_totals import (
        ArtifactEnrichmentReferenceDistroAdvisoriesTotals,
    )
    from ..models.artifact_enrichment_reference_enrichment_type_0 import ArtifactEnrichmentReferenceEnrichmentType0
    from ..models.artifact_enrichment_reference_score_breakdown import ArtifactEnrichmentReferenceScoreBreakdown
    from ..models.atomic_red_team_test import AtomicRedTeamTest
    from ..models.campaign_detail import CampaignDetail
    from ..models.capec_detail import CAPECDetail
    from ..models.cellular_annotation import CellularAnnotation
    from ..models.cellular_core_entry import CellularCoreEntry
    from ..models.cert_fr_advisory import CertFRAdvisory
    from ..models.cisa_campaign_advisory import CISACampaignAdvisory
    from ..models.citation import Citation
    from ..models.cve_reference import CVEReference
    from ..models.cwe_detail import CWEDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.defense_triad import DefenseTriad
    from ..models.detection_strategy import DetectionStrategy
    from ..models.distro_advisory import DistroAdvisory
    from ..models.error_detail import ErrorDetail
    from ..models.exploit_detail import ExploitDetail
    from ..models.f3_technique import F3Technique
    from ..models.fight_technique import FightTechnique
    from ..models.framework_object_detail import FrameworkObjectDetail
    from ..models.galaxy_cluster_detail import GalaxyClusterDetail
    from ..models.group_detail import GroupDetail
    from ..models.gtfo_bins_binary import GTFOBinsBinary
    from ..models.hijack_libs_entry import HijackLibsEntry
    from ..models.jvn_advisory import JVNAdvisory
    from ..models.kev_entry import KEVEntry
    from ..models.lev_estimate import LEVEstimate
    from ..models.location_detail import LocationDetail
    from ..models.log_source_group import LogSourceGroup
    from ..models.lolbas_binary import LOLBASBinary
    from ..models.metasploit_module import MetasploitModule
    from ..models.mitigation_detail import MitigationDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.nuclei_template import NucleiTemplate
    from ..models.osv_advisory import OSVAdvisory
    from ..models.ot_vendor_advisory import OTVendorAdvisory
    from ..models.risk_profile import RiskProfile
    from ..models.sector_detail import SectorDetail
    from ..models.software_detail import SoftwareDetail
    from ..models.source_stamp import SourceStamp
    from ..models.ssvc_decision import SSVCDecision
    from ..models.technique_detail import TechniqueDetail
    from ..models.timeline_event import TimelineEvent
    from ..models.vendor_advisory import VendorAdvisory


T = TypeVar("T", bound="ArtifactEnrichmentReference")


@_attrs_define
class ArtifactEnrichmentReference:
    """One extracted reference, fully enriched, graded, scored, and decided.

    Scoring and grading are deterministic. `ssvc` and `action` are first-class fields.

        Attributes:
            id (str): Stable 12-character reference ID derived as the first 12 hex chars of ``sha1(f'{type}:{value}')`` —
                same enrichment, same input → same ID across runs. Used by the Report Builder to cite references, by exporters
                for cross-format linkage, and by future enrichment-diff/continuous-monitoring workflows.
            type_ (ArtifactEnrichmentReferenceType): Reference type extracted from the artifact
            value (str): The reference value (e.g. CVE-2024-1234, 1.2.3.4, cpe:2.3:…, T1059)
            action (ArtifactEnrichmentReferenceActionType0 | None | Unset): Action vocabulary derived from the SSVC decision
                (or BLOCK for IOCs)
            advisories (list[OSVAdvisory] | Unset): Non-CVE OSV advisories for a PACKAGE (purl) reference — the
                GHSA-/PYSEC-/RUSTSEC-/GO-only ecosystem advisories OSV reports that carry NO CVE id (a large share of
                npm/PyPI/Go/crates findings). CVE-aliased OSV advisories already drive the reference's score via its nested
                CVEs; these have no other home, so without surfacing them a package vulnerable only via a GHSA would show zero
                advisory detail. Full OSVAdvisory shape (severity, fix ranges, references) — the artifact-enricher package probe
                requests the OSV verbosity. Package refs only.
            affected_configurations (list[AffectedConfiguration] | Unset): Affected products and version ranges from NVD
                configurations, deduplicated (first 100)
            affected_configurations_total (int | Unset): Distinct affected configurations before the cap Default: 0.
            android_bulletin (AndroidBulletin | None | Unset): The Android Security Bulletin record this CVE's OSV aliases
                name (`ASB-A-*`). CVE refs only; one OSV record read, the same host the `osv` layer already reads.
            atlas_mitigations (list[MitigationDetail] | Unset): MITRE ATLAS mitigations for an ATLAS technique
            atomic_tests (list[AtomicRedTeamTest] | Unset): Atomic Red Team tests exercising this ATT&CK technique (first
                50; see `atomic_tests_total`) — name, GUID, supported platforms, executor and elevation flag only. Technique
                refs only; opt-in via include=['atomic_red_team'].
            atomic_tests_total (int | Unset): Atomic Red Team tests matching this technique before the per-technique cap
                Default: 0.
            attack_pattern (CAPECDetail | None | Unset): CAPEC profile: likelihood, severity, prerequisites, skills
                required, execution flow
            campaign (CampaignDetail | None | Unset): ATT&CK campaign profile (first/last seen + citations)
            cellular_annotations (list[CellularAnnotation] | Unset): Rows of the 5G CVE-annotated dataset (Zenodo 17450053,
                CC-BY-4.0) for this CVE. CVE refs only; an in-process read of the committed corpus.
            cellular_core_entries (list[CellularCoreEntry] | Unset): The RANsacked cellular-core implementation row for this
                CVE. CVE refs only; opt-in via include=['cellular_core'].
            certfr_advisories (list[CertFRAdvisory] | Unset): CERT-FR (ANSSI) advisories and alerts that reference this CVE,
                with the reference id, title, last revision date, canonical page URL, CVE ids, the advisory's own `scada` flag,
                affected vendors/products and its published risk descriptions — link and metadata only, never the advisory body.
                Opt-in via include=['certfr_advisories']; read from the seeded corpus. A missing corpus is []; a corrupt one is
                [] plus an `errors[]` entry (step `fetch_certfr`).
            cisa_campaigns (list[CISACampaignAdvisory] | Unset): CISA joint AA-series advisories whose STIX bundle names
                this CVE. CVE refs only; an in-process read of the seeded corpus.
            citations (list[Citation] | Unset): Per-reference graded citations
            cna_assigner (None | str | Unset): Authoritative CNA (CVE Numbering Authority) that assigned the CVE — e.g.
                'Cisco PSIRT', 'MITRE'. Sourced from the CVE bundle's STIX created_by_ref/assigner. CVE refs only.
            confidence (ArtifactEnrichmentReferenceConfidenceType0 | None | Unset): Analytic confidence (multi-source
                corroboration)
            countered_techniques (list[str] | Unset): ATT&CK technique ids a D3FEND countermeasure defends against (D3FEND
                mapping)
            cve_references (list[CVEReference] | Unset): The CVE record's reference links with their tags
            cvss_v2_score (float | None | Unset): CVSS v2.0 base score
            cvss_v2_severity (None | str | Unset): CVSS v2.0 severity
            cvss_v2_vector (None | str | Unset): CVSS v2.0 vector string
            cvss_v3_score (float | None | Unset): CVSS v3.x base score
            cvss_v3_severity (None | str | Unset): CVSS v3.x severity
            cvss_v3_vector (None | str | Unset): CVSS v3.x vector string (CVSS:3.1/...)
            cvss_v3_version (None | str | Unset): Which v3 revision the `cvss_v3_*` fields hold — '3.1' or '3.0'
            cvss_v4_score (float | None | Unset): CVSS v4.0 base score
            cvss_v4_severity (None | str | Unset): CVSS v4.0 severity
            cvss_v4_vector (None | str | Unset): CVSS v4.0 vector string (CVSS:4.0/...)
            cwe_ids (list[str] | Unset): CWE weaknesses the CVE record names (e.g. ['CWE-78'])
            d3fend (D3FENDDetail | None | Unset): MITRE D3FEND countermeasure for a d3fend reference
            defense_score (float | None | Unset): 0-100 deterministic DEFENSE-readiness score for this reference — how well
                its ATT&CK techniques are covered by detections / mitigations / D3FEND counters (detection weighted highest).
                The symmetric counterpart to ``score``. Null when the reference has no mapped ATT&CK techniques (coverage can't
                be assessed).
            defenses (list[DefenseTriad] | Unset): Per-technique detect/mitigate/counter triads
            detection_strategies (list[DetectionStrategy] | Unset): ATT&CK v18 detection strategies for this technique, each
                with its analytics
            distro_advisories (list[DistroAdvisory] | Unset): Linux distro advisories for this CVE (SUSE CSAF-VEX, Ubuntu
                OpenVEX, Alpine secdb), direct CVE refs only. Capped at 200 rows per source; `distro_advisories_totals` and
                `distro_advisories_truncated` say what the cap cut.
            distro_advisories_totals (ArtifactEnrichmentReferenceDistroAdvisoriesTotals | Unset): Rows each distro source
                produced before the 200-row cap, keyed by source
            distro_advisories_truncated (bool | Unset): True when any distro source produced more rows than the cap lists
                Default: False.
            enrichment (ArtifactEnrichmentReferenceEnrichmentType0 | None | Unset): Curated per-reference details returned
                only with `include=['enrichment']`. Contains descriptive and relationship context that has no dedicated top-
                level field. CVSS, EPSS, and KEV values remain in their typed top-level fields; raw source payloads are not
                returned.
            epss (float | None | Unset): EPSS probability (0-1)
            epss_percentile (float | None | Unset): EPSS percentile (0-1): rank among all scored CVEs; not a probability
            epss_trend (None | str | Unset): EPSS velocity trend (rising/stable/falling/…)
            errors (list[ErrorDetail] | Unset): Per-reference partial-failure details
            evidence_excerpt (None | str | Unset): ±120 chars of the SOURCE DOCUMENT around this reference's first
                occurrence — the analyst's own words. The enricher deliberately does not model incident-specific uncertainty
                ('probed but not confirmed'); this carries that prose context alongside the deterministic verdict so a human can
                weigh both. Best-effort: null when the value never appears verbatim (parsed CPEs, file-format extractors).
            exploit_maturity (ArtifactEnrichmentReferenceExploitMaturityType0 | None | Unset): Exploit maturity (cvss-bt
                priority tree: KEV/active→attacked, PoC→poc, else unproven)
            exploits (list[ExploitDetail] | Unset): Authoritative exploit objects from ExploitDB public exploit evidence
                (real exploit evidence — type + references + STIX id). CVE refs only. Stronger signal than the PoC count.
            extractor (None | str | Unset): Which extractor produced the ref (regex | nmap_xml | csv | …)
            f3_techniques (list[F3Technique] | Unset): MITRE F3 fraud techniques that carry this ATT&CK technique's id
            fight_techniques (list[FightTechnique] | Unset): MITRE FiGHT 5G techniques whose own `FGT` id maps onto this
                ATT&CK technique. Technique refs only; opt-in via include=['fight'].
            fixed_versions (list[str] | Unset): Fixed versions from the OSV.dev advisories aliased to this CVE (every
                ecosystem, sorted)
            framework (None | str | Unset): ATT&CK framework for technique refs (enterprise | ics) — disambiguates the
                shared T#### id space
            framework_technique (FrameworkObjectDetail | None | TechniqueDetail | Unset): ATLAS / DISARM / F3 / CLOAK
                technique profile (description, tactics, platforms)
            galaxy_clusters (list[GalaxyClusterDetail] | Unset): Full MISP Galaxy cluster profiles referenced by this
                reference's MISP attributes — threat-actor / malware / tool / technique clusters with aliases, source,
                description, and relations. IOC refs only.
            grade (AdmiraltyGrade | None | Unset): Deterministic NATO Admiralty grade for this reference
            group (GroupDetail | None | Unset): ATT&CK threat group profile (aliases, first/last seen)
            group_activity (ActivitySummary | None | Unset): Group activity: active flag, campaign count
            group_risk (None | RiskProfile | Unset): Group damage potential: exploitable and KEV CVEs reachable through its
                techniques
            gtfobins_binaries (list[GTFOBinsBinary] | Unset): GTFOBins tools whose categories map onto this ATT&CK technique
                (first 50; see `gtfobins_binaries_total`) — names, categories and the project page only. Technique refs only;
                carried by include=['lotl'].
            gtfobins_binaries_total (int | Unset): GTFOBins tools matching this technique before the per-technique cap
                Default: 0.
            hijacklibs_entries (list[HijackLibsEntry] | Unset): HijackLibs DLL hijacks whose type maps onto this ATT&CK
                technique (first 50; see `hijacklibs_entries_total`) — names, paths and vendor only. Technique refs only;
                carried by include=['lotl'].
            hijacklibs_entries_total (int | Unset): HijackLibs entries matching this technique before the per-technique cap
                Default: 0.
            ioc_type (None | str | Unset): Indicator subtype for IOC refs (ip-dst | domain | url | hash)
            jvn_advisories (list[JVNAdvisory] | Unset): JVNDB advisories referencing this CVE — link and metadata rows only.
                CVE refs only; opt-in via include=['jvn'].
            kev (KEVEntry | None | Unset): The full CISA KEV record when listed: required action, notes, date added, due
                date, vendor/product, ransomware use, CWEs, and CISA's forensic-triage flag
            kev_due_date (None | str | Unset): CISA KEV remediation deadline, when listed
            kev_ransomware (bool | Unset): Linked to a known ransomware campaign (CISA KEV) Default: False.
            last_modified (None | str | Unset): CVE record last-modified date (ISO 8601)
            lev (LEVEstimate | None | Unset): NIST LEV2: lower bound on the probability it was already exploited (EPSS
                history on record)
            likelihood (ArtifactEnrichmentReferenceLikelihoodType0 | None | Unset): ICD-203 Words-of-Estimative-Probability
                band (derived from the score)
            location (LocationDetail | None | Unset): Country or region profile (ISO 3166-1 / UN M49 hierarchy) for a
                location reference
            log_sources (list[LogSourceGroup] | Unset): Log sources that observe the technique, grouped by source with their
                channels
            lolbas_binaries (list[LOLBASBinary] | Unset): LOLBAS binaries whose commands declare this ATT&CK technique —
                names, ids and the project page only. Technique refs only; opt-in via include=['lolbas'].
            metasploit_modules (list[MetasploitModule] | Unset): Metasploit Framework modules naming this CVE (rank,
                platforms, reliability notes)
            nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate techniques mapped
                to this reference. Each entry identifies the control, family, ATT&CK technique, and mapping rationale.
            nuclei_templates (list[NucleiTemplate] | Unset): Nuclei detection templates naming this CVE
            osv_ids (list[str] | Unset): OSV.dev / GHSA advisory ids aliased to this CVE
            ot_vendor_advisories (list[OTVendorAdvisory] | Unset): Direct OT/embedded vendor advisories naming this CVE —
                Rockwell Automation and MediaTek (`ot_vendor_advisories[]`), with CVE ids, CVSS scores, products and MediaTek
                chipset codes. Link and metadata only. Opt-in via include=['ot_vendor_advisories']; a zero-cost in-process read
                of the seeded corpus.
            platforms (list[str] | Unset): Platforms the ATT&CK technique applies to
            provenance (list[SourceStamp] | Unset): Which source supplied which fields, with its as-of date
            published (None | str | Unset): CVE publication date (ISO 8601)
            recent_misp_event_date (None | str | Unset): Most recent MISP event date this reference appears in (ISO date).
                For IOCs, signals recency of last sighting; older dates indicate stale corroboration.
            score (float | None | Unset): 0-100 deterministic priority (attack) score
            score_breakdown (ArtifactEnrichmentReferenceScoreBreakdown | Unset): Per-signal contributions to the score
            sector (None | SectorDetail | Unset): Industry sector profile for a sector reference
            signal_sources (list[str] | Unset): Intelligence sources that contributed a signal
            software (None | SoftwareDetail | Unset): ATT&CK malware / tool profile
            source_artifact_ids (list[str] | Unset): Ids of the attached artifacts this reference came from — the UNION of
                the sources of every block the value appeared in (a value named in one artifact's text block and again in
                another file carries both ids). Attribution is structural only: an entry of `texts` with no
                `source_artifact_id`, and any legacy `text` no artifact id names, contribute NOTHING, so a value found only in
                unnamed content stays empty here rather than being assigned to a named source. Empty therefore means 'no per-
                reference attribution is provable', never 'this had no source' — read `attachment_sources` for the report's
                whole provenance.
            source_location (None | str | Unset): Where in the artifact the ref was found (line/row/page)
            ssvc (None | SSVCDecision | Unset): Deterministic SSVC decision (CVE/product lane)
            tactics (list[str] | Unset): ATT&CK tactics the technique serves
            techniques_provenance (ArtifactEnrichmentReferenceTechniquesProvenanceType0 | None | Unset): Precision class for
                linked ATT&CK techniques on this reference: `cwe_closure` for a specific CWE's closure, `cwe_class` for a
                generic CWE's closure, `heuristic` for indirect evidence. `cve_specific` only when the CVE records no CWE.
            threat_actors_origin (list[str] | Unset): Threat actors the MISP threat-actor galaxy attributes to this country
                (location refs)
            threat_actors_targeting (list[str] | Unset): Threat actors the MISP threat-actor galaxy lists as targeting this
                country or sector (`cfr-suspected-victims` / `cfr-target-category` / `targeted-sector`)
            timeline (list[TimelineEvent] | Unset): Chronological narrative for this reference — disclosure, KEV listing,
                KEV deadline, first PoC, and EPSS-trajectory inflection (when derivable from the score timeseries). All events
                are pure derivations from already-fetched fields; no invented signals.
            vendor_advisories (list[VendorAdvisory] | Unset): Vendor PSIRT advisories for this CVE (MSRC, Red Hat, Cisco) —
                direct CVE refs only
            vuln_status (None | str | Unset): NVD processing status (Analyzed, Modified, Deferred, …)
            weakness (CWEDetail | None | Unset): CWE profile: likelihood of exploit, consequences, detection methods, modes
                of introduction
    """

    id: str
    type_: ArtifactEnrichmentReferenceType
    value: str
    action: ArtifactEnrichmentReferenceActionType0 | None | Unset = UNSET
    advisories: list[OSVAdvisory] | Unset = UNSET
    affected_configurations: list[AffectedConfiguration] | Unset = UNSET
    affected_configurations_total: int | Unset = 0
    android_bulletin: AndroidBulletin | None | Unset = UNSET
    atlas_mitigations: list[MitigationDetail] | Unset = UNSET
    atomic_tests: list[AtomicRedTeamTest] | Unset = UNSET
    atomic_tests_total: int | Unset = 0
    attack_pattern: CAPECDetail | None | Unset = UNSET
    campaign: CampaignDetail | None | Unset = UNSET
    cellular_annotations: list[CellularAnnotation] | Unset = UNSET
    cellular_core_entries: list[CellularCoreEntry] | Unset = UNSET
    certfr_advisories: list[CertFRAdvisory] | Unset = UNSET
    cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
    citations: list[Citation] | Unset = UNSET
    cna_assigner: None | str | Unset = UNSET
    confidence: ArtifactEnrichmentReferenceConfidenceType0 | None | Unset = UNSET
    countered_techniques: list[str] | Unset = UNSET
    cve_references: list[CVEReference] | Unset = UNSET
    cvss_v2_score: float | None | Unset = UNSET
    cvss_v2_severity: None | str | Unset = UNSET
    cvss_v2_vector: None | str | Unset = UNSET
    cvss_v3_score: float | None | Unset = UNSET
    cvss_v3_severity: None | str | Unset = UNSET
    cvss_v3_vector: None | str | Unset = UNSET
    cvss_v3_version: None | str | Unset = UNSET
    cvss_v4_score: float | None | Unset = UNSET
    cvss_v4_severity: None | str | Unset = UNSET
    cvss_v4_vector: None | str | Unset = UNSET
    cwe_ids: list[str] | Unset = UNSET
    d3fend: D3FENDDetail | None | Unset = UNSET
    defense_score: float | None | Unset = UNSET
    defenses: list[DefenseTriad] | Unset = UNSET
    detection_strategies: list[DetectionStrategy] | Unset = UNSET
    distro_advisories: list[DistroAdvisory] | Unset = UNSET
    distro_advisories_totals: ArtifactEnrichmentReferenceDistroAdvisoriesTotals | Unset = UNSET
    distro_advisories_truncated: bool | Unset = False
    enrichment: ArtifactEnrichmentReferenceEnrichmentType0 | None | Unset = UNSET
    epss: float | None | Unset = UNSET
    epss_percentile: float | None | Unset = UNSET
    epss_trend: None | str | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    evidence_excerpt: None | str | Unset = UNSET
    exploit_maturity: ArtifactEnrichmentReferenceExploitMaturityType0 | None | Unset = UNSET
    exploits: list[ExploitDetail] | Unset = UNSET
    extractor: None | str | Unset = UNSET
    f3_techniques: list[F3Technique] | Unset = UNSET
    fight_techniques: list[FightTechnique] | Unset = UNSET
    fixed_versions: list[str] | Unset = UNSET
    framework: None | str | Unset = UNSET
    framework_technique: FrameworkObjectDetail | None | TechniqueDetail | Unset = UNSET
    galaxy_clusters: list[GalaxyClusterDetail] | Unset = UNSET
    grade: AdmiraltyGrade | None | Unset = UNSET
    group: GroupDetail | None | Unset = UNSET
    group_activity: ActivitySummary | None | Unset = UNSET
    group_risk: None | RiskProfile | Unset = UNSET
    gtfobins_binaries: list[GTFOBinsBinary] | Unset = UNSET
    gtfobins_binaries_total: int | Unset = 0
    hijacklibs_entries: list[HijackLibsEntry] | Unset = UNSET
    hijacklibs_entries_total: int | Unset = 0
    ioc_type: None | str | Unset = UNSET
    jvn_advisories: list[JVNAdvisory] | Unset = UNSET
    kev: KEVEntry | None | Unset = UNSET
    kev_due_date: None | str | Unset = UNSET
    kev_ransomware: bool | Unset = False
    last_modified: None | str | Unset = UNSET
    lev: LEVEstimate | None | Unset = UNSET
    likelihood: ArtifactEnrichmentReferenceLikelihoodType0 | None | Unset = UNSET
    location: LocationDetail | None | Unset = UNSET
    log_sources: list[LogSourceGroup] | Unset = UNSET
    lolbas_binaries: list[LOLBASBinary] | Unset = UNSET
    metasploit_modules: list[MetasploitModule] | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    nuclei_templates: list[NucleiTemplate] | Unset = UNSET
    osv_ids: list[str] | Unset = UNSET
    ot_vendor_advisories: list[OTVendorAdvisory] | Unset = UNSET
    platforms: list[str] | Unset = UNSET
    provenance: list[SourceStamp] | Unset = UNSET
    published: None | str | Unset = UNSET
    recent_misp_event_date: None | str | Unset = UNSET
    score: float | None | Unset = UNSET
    score_breakdown: ArtifactEnrichmentReferenceScoreBreakdown | Unset = UNSET
    sector: None | SectorDetail | Unset = UNSET
    signal_sources: list[str] | Unset = UNSET
    software: None | SoftwareDetail | Unset = UNSET
    source_artifact_ids: list[str] | Unset = UNSET
    source_location: None | str | Unset = UNSET
    ssvc: None | SSVCDecision | Unset = UNSET
    tactics: list[str] | Unset = UNSET
    techniques_provenance: ArtifactEnrichmentReferenceTechniquesProvenanceType0 | None | Unset = UNSET
    threat_actors_origin: list[str] | Unset = UNSET
    threat_actors_targeting: list[str] | Unset = UNSET
    timeline: list[TimelineEvent] | Unset = UNSET
    vendor_advisories: list[VendorAdvisory] | Unset = UNSET
    vuln_status: None | str | Unset = UNSET
    weakness: CWEDetail | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.activity_summary import ActivitySummary  # noqa: PLC0415
        from ..models.admiralty_grade import AdmiraltyGrade  # noqa: PLC0415
        from ..models.affected_configuration import AffectedConfiguration  # noqa: PLC0415
        from ..models.android_bulletin import AndroidBulletin  # noqa: PLC0415
        from ..models.artifact_enrichment_reference_distro_advisories_totals import (
            ArtifactEnrichmentReferenceDistroAdvisoriesTotals,  # noqa: PLC0415
        )
        from ..models.artifact_enrichment_reference_enrichment_type_0 import (
            ArtifactEnrichmentReferenceEnrichmentType0,  # noqa: PLC0415
        )
        from ..models.artifact_enrichment_reference_score_breakdown import (
            ArtifactEnrichmentReferenceScoreBreakdown,  # noqa: PLC0415
        )
        from ..models.atomic_red_team_test import AtomicRedTeamTest  # noqa: PLC0415
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.capec_detail import CAPECDetail  # noqa: PLC0415
        from ..models.cellular_annotation import CellularAnnotation  # noqa: PLC0415
        from ..models.cellular_core_entry import CellularCoreEntry  # noqa: PLC0415
        from ..models.cert_fr_advisory import CertFRAdvisory  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.citation import Citation  # noqa: PLC0415
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.cwe_detail import CWEDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.defense_triad import DefenseTriad  # noqa: PLC0415
        from ..models.detection_strategy import DetectionStrategy  # noqa: PLC0415
        from ..models.distro_advisory import DistroAdvisory  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.exploit_detail import ExploitDetail  # noqa: PLC0415
        from ..models.f3_technique import F3Technique  # noqa: PLC0415
        from ..models.fight_technique import FightTechnique  # noqa: PLC0415
        from ..models.framework_object_detail import FrameworkObjectDetail  # noqa: PLC0415
        from ..models.galaxy_cluster_detail import GalaxyClusterDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.gtfo_bins_binary import GTFOBinsBinary  # noqa: PLC0415
        from ..models.hijack_libs_entry import HijackLibsEntry  # noqa: PLC0415
        from ..models.jvn_advisory import JVNAdvisory  # noqa: PLC0415
        from ..models.kev_entry import KEVEntry  # noqa: PLC0415
        from ..models.lev_estimate import LEVEstimate  # noqa: PLC0415
        from ..models.location_detail import LocationDetail  # noqa: PLC0415
        from ..models.log_source_group import LogSourceGroup  # noqa: PLC0415
        from ..models.lolbas_binary import LOLBASBinary  # noqa: PLC0415
        from ..models.metasploit_module import MetasploitModule  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.nuclei_template import NucleiTemplate  # noqa: PLC0415
        from ..models.osv_advisory import OSVAdvisory  # noqa: PLC0415
        from ..models.ot_vendor_advisory import OTVendorAdvisory  # noqa: PLC0415
        from ..models.risk_profile import RiskProfile  # noqa: PLC0415
        from ..models.sector_detail import SectorDetail  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.source_stamp import SourceStamp  # noqa: PLC0415
        from ..models.ssvc_decision import SSVCDecision  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.timeline_event import TimelineEvent  # noqa: PLC0415
        from ..models.vendor_advisory import VendorAdvisory  # noqa: PLC0415

        id = self.id

        type_ = self.type_.value

        value = self.value

        action: None | str | Unset
        if isinstance(self.action, Unset):
            action = UNSET
        elif isinstance(self.action, ArtifactEnrichmentReferenceActionType0):
            action = self.action.value
        else:
            action = self.action

        advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.advisories, Unset):
            advisories = []
            for advisories_item_data in self.advisories:
                advisories_item = advisories_item_data.to_dict()
                advisories.append(advisories_item)

        affected_configurations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_configurations, Unset):
            affected_configurations = []
            for affected_configurations_item_data in self.affected_configurations:
                affected_configurations_item = affected_configurations_item_data.to_dict()
                affected_configurations.append(affected_configurations_item)

        affected_configurations_total = self.affected_configurations_total

        android_bulletin: dict[str, Any] | None | Unset
        if isinstance(self.android_bulletin, Unset):
            android_bulletin = UNSET
        elif isinstance(self.android_bulletin, AndroidBulletin):
            android_bulletin = self.android_bulletin.to_dict()
        else:
            android_bulletin = self.android_bulletin

        atlas_mitigations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.atlas_mitigations, Unset):
            atlas_mitigations = []
            for atlas_mitigations_item_data in self.atlas_mitigations:
                atlas_mitigations_item = atlas_mitigations_item_data.to_dict()
                atlas_mitigations.append(atlas_mitigations_item)

        atomic_tests: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.atomic_tests, Unset):
            atomic_tests = []
            for atomic_tests_item_data in self.atomic_tests:
                atomic_tests_item = atomic_tests_item_data.to_dict()
                atomic_tests.append(atomic_tests_item)

        atomic_tests_total = self.atomic_tests_total

        attack_pattern: dict[str, Any] | None | Unset
        if isinstance(self.attack_pattern, Unset):
            attack_pattern = UNSET
        elif isinstance(self.attack_pattern, CAPECDetail):
            attack_pattern = self.attack_pattern.to_dict()
        else:
            attack_pattern = self.attack_pattern

        campaign: dict[str, Any] | None | Unset
        if isinstance(self.campaign, Unset):
            campaign = UNSET
        elif isinstance(self.campaign, CampaignDetail):
            campaign = self.campaign.to_dict()
        else:
            campaign = self.campaign

        cellular_annotations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cellular_annotations, Unset):
            cellular_annotations = []
            for cellular_annotations_item_data in self.cellular_annotations:
                cellular_annotations_item = cellular_annotations_item_data.to_dict()
                cellular_annotations.append(cellular_annotations_item)

        cellular_core_entries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cellular_core_entries, Unset):
            cellular_core_entries = []
            for cellular_core_entries_item_data in self.cellular_core_entries:
                cellular_core_entries_item = cellular_core_entries_item_data.to_dict()
                cellular_core_entries.append(cellular_core_entries_item)

        certfr_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.certfr_advisories, Unset):
            certfr_advisories = []
            for certfr_advisories_item_data in self.certfr_advisories:
                certfr_advisories_item = certfr_advisories_item_data.to_dict()
                certfr_advisories.append(certfr_advisories_item)

        cisa_campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cisa_campaigns, Unset):
            cisa_campaigns = []
            for cisa_campaigns_item_data in self.cisa_campaigns:
                cisa_campaigns_item = cisa_campaigns_item_data.to_dict()
                cisa_campaigns.append(cisa_campaigns_item)

        citations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.citations, Unset):
            citations = []
            for citations_item_data in self.citations:
                citations_item = citations_item_data.to_dict()
                citations.append(citations_item)

        cna_assigner: None | str | Unset
        if isinstance(self.cna_assigner, Unset):
            cna_assigner = UNSET
        else:
            cna_assigner = self.cna_assigner

        confidence: None | str | Unset
        if isinstance(self.confidence, Unset):
            confidence = UNSET
        elif isinstance(self.confidence, ArtifactEnrichmentReferenceConfidenceType0):
            confidence = self.confidence.value
        else:
            confidence = self.confidence

        countered_techniques: list[str] | Unset = UNSET
        if not isinstance(self.countered_techniques, Unset):
            countered_techniques = self.countered_techniques

        cve_references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cve_references, Unset):
            cve_references = []
            for cve_references_item_data in self.cve_references:
                cve_references_item = cve_references_item_data.to_dict()
                cve_references.append(cve_references_item)

        cvss_v2_score: float | None | Unset
        if isinstance(self.cvss_v2_score, Unset):
            cvss_v2_score = UNSET
        else:
            cvss_v2_score = self.cvss_v2_score

        cvss_v2_severity: None | str | Unset
        if isinstance(self.cvss_v2_severity, Unset):
            cvss_v2_severity = UNSET
        else:
            cvss_v2_severity = self.cvss_v2_severity

        cvss_v2_vector: None | str | Unset
        if isinstance(self.cvss_v2_vector, Unset):
            cvss_v2_vector = UNSET
        else:
            cvss_v2_vector = self.cvss_v2_vector

        cvss_v3_score: float | None | Unset
        if isinstance(self.cvss_v3_score, Unset):
            cvss_v3_score = UNSET
        else:
            cvss_v3_score = self.cvss_v3_score

        cvss_v3_severity: None | str | Unset
        if isinstance(self.cvss_v3_severity, Unset):
            cvss_v3_severity = UNSET
        else:
            cvss_v3_severity = self.cvss_v3_severity

        cvss_v3_vector: None | str | Unset
        if isinstance(self.cvss_v3_vector, Unset):
            cvss_v3_vector = UNSET
        else:
            cvss_v3_vector = self.cvss_v3_vector

        cvss_v3_version: None | str | Unset
        if isinstance(self.cvss_v3_version, Unset):
            cvss_v3_version = UNSET
        else:
            cvss_v3_version = self.cvss_v3_version

        cvss_v4_score: float | None | Unset
        if isinstance(self.cvss_v4_score, Unset):
            cvss_v4_score = UNSET
        else:
            cvss_v4_score = self.cvss_v4_score

        cvss_v4_severity: None | str | Unset
        if isinstance(self.cvss_v4_severity, Unset):
            cvss_v4_severity = UNSET
        else:
            cvss_v4_severity = self.cvss_v4_severity

        cvss_v4_vector: None | str | Unset
        if isinstance(self.cvss_v4_vector, Unset):
            cvss_v4_vector = UNSET
        else:
            cvss_v4_vector = self.cvss_v4_vector

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        d3fend: dict[str, Any] | None | Unset
        if isinstance(self.d3fend, Unset):
            d3fend = UNSET
        elif isinstance(self.d3fend, D3FENDDetail):
            d3fend = self.d3fend.to_dict()
        else:
            d3fend = self.d3fend

        defense_score: float | None | Unset
        if isinstance(self.defense_score, Unset):
            defense_score = UNSET
        else:
            defense_score = self.defense_score

        defenses: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.defenses, Unset):
            defenses = []
            for defenses_item_data in self.defenses:
                defenses_item = defenses_item_data.to_dict()
                defenses.append(defenses_item)

        detection_strategies: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.detection_strategies, Unset):
            detection_strategies = []
            for detection_strategies_item_data in self.detection_strategies:
                detection_strategies_item = detection_strategies_item_data.to_dict()
                detection_strategies.append(detection_strategies_item)

        distro_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.distro_advisories, Unset):
            distro_advisories = []
            for distro_advisories_item_data in self.distro_advisories:
                distro_advisories_item = distro_advisories_item_data.to_dict()
                distro_advisories.append(distro_advisories_item)

        distro_advisories_totals: dict[str, Any] | Unset = UNSET
        if not isinstance(self.distro_advisories_totals, Unset):
            distro_advisories_totals = self.distro_advisories_totals.to_dict()

        distro_advisories_truncated = self.distro_advisories_truncated

        enrichment: dict[str, Any] | None | Unset
        if isinstance(self.enrichment, Unset):
            enrichment = UNSET
        elif isinstance(self.enrichment, ArtifactEnrichmentReferenceEnrichmentType0):
            enrichment = self.enrichment.to_dict()
        else:
            enrichment = self.enrichment

        epss: float | None | Unset
        if isinstance(self.epss, Unset):
            epss = UNSET
        else:
            epss = self.epss

        epss_percentile: float | None | Unset
        if isinstance(self.epss_percentile, Unset):
            epss_percentile = UNSET
        else:
            epss_percentile = self.epss_percentile

        epss_trend: None | str | Unset
        if isinstance(self.epss_trend, Unset):
            epss_trend = UNSET
        else:
            epss_trend = self.epss_trend

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        evidence_excerpt: None | str | Unset
        if isinstance(self.evidence_excerpt, Unset):
            evidence_excerpt = UNSET
        else:
            evidence_excerpt = self.evidence_excerpt

        exploit_maturity: None | str | Unset
        if isinstance(self.exploit_maturity, Unset):
            exploit_maturity = UNSET
        elif isinstance(self.exploit_maturity, ArtifactEnrichmentReferenceExploitMaturityType0):
            exploit_maturity = self.exploit_maturity.value
        else:
            exploit_maturity = self.exploit_maturity

        exploits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.exploits, Unset):
            exploits = []
            for exploits_item_data in self.exploits:
                exploits_item = exploits_item_data.to_dict()
                exploits.append(exploits_item)

        extractor: None | str | Unset
        if isinstance(self.extractor, Unset):
            extractor = UNSET
        else:
            extractor = self.extractor

        f3_techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.f3_techniques, Unset):
            f3_techniques = []
            for f3_techniques_item_data in self.f3_techniques:
                f3_techniques_item = f3_techniques_item_data.to_dict()
                f3_techniques.append(f3_techniques_item)

        fight_techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.fight_techniques, Unset):
            fight_techniques = []
            for fight_techniques_item_data in self.fight_techniques:
                fight_techniques_item = fight_techniques_item_data.to_dict()
                fight_techniques.append(fight_techniques_item)

        fixed_versions: list[str] | Unset = UNSET
        if not isinstance(self.fixed_versions, Unset):
            fixed_versions = self.fixed_versions

        framework: None | str | Unset
        if isinstance(self.framework, Unset):
            framework = UNSET
        else:
            framework = self.framework

        framework_technique: dict[str, Any] | None | Unset
        if isinstance(self.framework_technique, Unset):
            framework_technique = UNSET
        elif isinstance(self.framework_technique, TechniqueDetail):
            framework_technique = self.framework_technique.to_dict()
        elif isinstance(self.framework_technique, FrameworkObjectDetail):
            framework_technique = self.framework_technique.to_dict()
        else:
            framework_technique = self.framework_technique

        galaxy_clusters: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.galaxy_clusters, Unset):
            galaxy_clusters = []
            for galaxy_clusters_item_data in self.galaxy_clusters:
                galaxy_clusters_item = galaxy_clusters_item_data.to_dict()
                galaxy_clusters.append(galaxy_clusters_item)

        grade: dict[str, Any] | None | Unset
        if isinstance(self.grade, Unset):
            grade = UNSET
        elif isinstance(self.grade, AdmiraltyGrade):
            grade = self.grade.to_dict()
        else:
            grade = self.grade

        group: dict[str, Any] | None | Unset
        if isinstance(self.group, Unset):
            group = UNSET
        elif isinstance(self.group, GroupDetail):
            group = self.group.to_dict()
        else:
            group = self.group

        group_activity: dict[str, Any] | None | Unset
        if isinstance(self.group_activity, Unset):
            group_activity = UNSET
        elif isinstance(self.group_activity, ActivitySummary):
            group_activity = self.group_activity.to_dict()
        else:
            group_activity = self.group_activity

        group_risk: dict[str, Any] | None | Unset
        if isinstance(self.group_risk, Unset):
            group_risk = UNSET
        elif isinstance(self.group_risk, RiskProfile):
            group_risk = self.group_risk.to_dict()
        else:
            group_risk = self.group_risk

        gtfobins_binaries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.gtfobins_binaries, Unset):
            gtfobins_binaries = []
            for gtfobins_binaries_item_data in self.gtfobins_binaries:
                gtfobins_binaries_item = gtfobins_binaries_item_data.to_dict()
                gtfobins_binaries.append(gtfobins_binaries_item)

        gtfobins_binaries_total = self.gtfobins_binaries_total

        hijacklibs_entries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.hijacklibs_entries, Unset):
            hijacklibs_entries = []
            for hijacklibs_entries_item_data in self.hijacklibs_entries:
                hijacklibs_entries_item = hijacklibs_entries_item_data.to_dict()
                hijacklibs_entries.append(hijacklibs_entries_item)

        hijacklibs_entries_total = self.hijacklibs_entries_total

        ioc_type: None | str | Unset
        if isinstance(self.ioc_type, Unset):
            ioc_type = UNSET
        else:
            ioc_type = self.ioc_type

        jvn_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.jvn_advisories, Unset):
            jvn_advisories = []
            for jvn_advisories_item_data in self.jvn_advisories:
                jvn_advisories_item = jvn_advisories_item_data.to_dict()
                jvn_advisories.append(jvn_advisories_item)

        kev: dict[str, Any] | None | Unset
        if isinstance(self.kev, Unset):
            kev = UNSET
        elif isinstance(self.kev, KEVEntry):
            kev = self.kev.to_dict()
        else:
            kev = self.kev

        kev_due_date: None | str | Unset
        if isinstance(self.kev_due_date, Unset):
            kev_due_date = UNSET
        else:
            kev_due_date = self.kev_due_date

        kev_ransomware = self.kev_ransomware

        last_modified: None | str | Unset
        if isinstance(self.last_modified, Unset):
            last_modified = UNSET
        else:
            last_modified = self.last_modified

        lev: dict[str, Any] | None | Unset
        if isinstance(self.lev, Unset):
            lev = UNSET
        elif isinstance(self.lev, LEVEstimate):
            lev = self.lev.to_dict()
        else:
            lev = self.lev

        likelihood: None | str | Unset
        if isinstance(self.likelihood, Unset):
            likelihood = UNSET
        elif isinstance(self.likelihood, ArtifactEnrichmentReferenceLikelihoodType0):
            likelihood = self.likelihood.value
        else:
            likelihood = self.likelihood

        location: dict[str, Any] | None | Unset
        if isinstance(self.location, Unset):
            location = UNSET
        elif isinstance(self.location, LocationDetail):
            location = self.location.to_dict()
        else:
            location = self.location

        log_sources: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.log_sources, Unset):
            log_sources = []
            for log_sources_item_data in self.log_sources:
                log_sources_item = log_sources_item_data.to_dict()
                log_sources.append(log_sources_item)

        lolbas_binaries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.lolbas_binaries, Unset):
            lolbas_binaries = []
            for lolbas_binaries_item_data in self.lolbas_binaries:
                lolbas_binaries_item = lolbas_binaries_item_data.to_dict()
                lolbas_binaries.append(lolbas_binaries_item)

        metasploit_modules: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.metasploit_modules, Unset):
            metasploit_modules = []
            for metasploit_modules_item_data in self.metasploit_modules:
                metasploit_modules_item = metasploit_modules_item_data.to_dict()
                metasploit_modules.append(metasploit_modules_item)

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        nuclei_templates: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nuclei_templates, Unset):
            nuclei_templates = []
            for nuclei_templates_item_data in self.nuclei_templates:
                nuclei_templates_item = nuclei_templates_item_data.to_dict()
                nuclei_templates.append(nuclei_templates_item)

        osv_ids: list[str] | Unset = UNSET
        if not isinstance(self.osv_ids, Unset):
            osv_ids = self.osv_ids

        ot_vendor_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.ot_vendor_advisories, Unset):
            ot_vendor_advisories = []
            for ot_vendor_advisories_item_data in self.ot_vendor_advisories:
                ot_vendor_advisories_item = ot_vendor_advisories_item_data.to_dict()
                ot_vendor_advisories.append(ot_vendor_advisories_item)

        platforms: list[str] | Unset = UNSET
        if not isinstance(self.platforms, Unset):
            platforms = self.platforms

        provenance: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.provenance, Unset):
            provenance = []
            for provenance_item_data in self.provenance:
                provenance_item = provenance_item_data.to_dict()
                provenance.append(provenance_item)

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        recent_misp_event_date: None | str | Unset
        if isinstance(self.recent_misp_event_date, Unset):
            recent_misp_event_date = UNSET
        else:
            recent_misp_event_date = self.recent_misp_event_date

        score: float | None | Unset
        if isinstance(self.score, Unset):
            score = UNSET
        else:
            score = self.score

        score_breakdown: dict[str, Any] | Unset = UNSET
        if not isinstance(self.score_breakdown, Unset):
            score_breakdown = self.score_breakdown.to_dict()

        sector: dict[str, Any] | None | Unset
        if isinstance(self.sector, Unset):
            sector = UNSET
        elif isinstance(self.sector, SectorDetail):
            sector = self.sector.to_dict()
        else:
            sector = self.sector

        signal_sources: list[str] | Unset = UNSET
        if not isinstance(self.signal_sources, Unset):
            signal_sources = self.signal_sources

        software: dict[str, Any] | None | Unset
        if isinstance(self.software, Unset):
            software = UNSET
        elif isinstance(self.software, SoftwareDetail):
            software = self.software.to_dict()
        else:
            software = self.software

        source_artifact_ids: list[str] | Unset = UNSET
        if not isinstance(self.source_artifact_ids, Unset):
            source_artifact_ids = self.source_artifact_ids

        source_location: None | str | Unset
        if isinstance(self.source_location, Unset):
            source_location = UNSET
        else:
            source_location = self.source_location

        ssvc: dict[str, Any] | None | Unset
        if isinstance(self.ssvc, Unset):
            ssvc = UNSET
        elif isinstance(self.ssvc, SSVCDecision):
            ssvc = self.ssvc.to_dict()
        else:
            ssvc = self.ssvc

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        techniques_provenance: None | str | Unset
        if isinstance(self.techniques_provenance, Unset):
            techniques_provenance = UNSET
        elif isinstance(self.techniques_provenance, ArtifactEnrichmentReferenceTechniquesProvenanceType0):
            techniques_provenance = self.techniques_provenance.value
        else:
            techniques_provenance = self.techniques_provenance

        threat_actors_origin: list[str] | Unset = UNSET
        if not isinstance(self.threat_actors_origin, Unset):
            threat_actors_origin = self.threat_actors_origin

        threat_actors_targeting: list[str] | Unset = UNSET
        if not isinstance(self.threat_actors_targeting, Unset):
            threat_actors_targeting = self.threat_actors_targeting

        timeline: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.timeline, Unset):
            timeline = []
            for timeline_item_data in self.timeline:
                timeline_item = timeline_item_data.to_dict()
                timeline.append(timeline_item)

        vendor_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.vendor_advisories, Unset):
            vendor_advisories = []
            for vendor_advisories_item_data in self.vendor_advisories:
                vendor_advisories_item = vendor_advisories_item_data.to_dict()
                vendor_advisories.append(vendor_advisories_item)

        vuln_status: None | str | Unset
        if isinstance(self.vuln_status, Unset):
            vuln_status = UNSET
        else:
            vuln_status = self.vuln_status

        weakness: dict[str, Any] | None | Unset
        if isinstance(self.weakness, Unset):
            weakness = UNSET
        elif isinstance(self.weakness, CWEDetail):
            weakness = self.weakness.to_dict()
        else:
            weakness = self.weakness

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "type": type_,
                "value": value,
            }
        )
        if action is not UNSET:
            field_dict["action"] = action
        if advisories is not UNSET:
            field_dict["advisories"] = advisories
        if affected_configurations is not UNSET:
            field_dict["affected_configurations"] = affected_configurations
        if affected_configurations_total is not UNSET:
            field_dict["affected_configurations_total"] = affected_configurations_total
        if android_bulletin is not UNSET:
            field_dict["android_bulletin"] = android_bulletin
        if atlas_mitigations is not UNSET:
            field_dict["atlas_mitigations"] = atlas_mitigations
        if atomic_tests is not UNSET:
            field_dict["atomic_tests"] = atomic_tests
        if atomic_tests_total is not UNSET:
            field_dict["atomic_tests_total"] = atomic_tests_total
        if attack_pattern is not UNSET:
            field_dict["attack_pattern"] = attack_pattern
        if campaign is not UNSET:
            field_dict["campaign"] = campaign
        if cellular_annotations is not UNSET:
            field_dict["cellular_annotations"] = cellular_annotations
        if cellular_core_entries is not UNSET:
            field_dict["cellular_core_entries"] = cellular_core_entries
        if certfr_advisories is not UNSET:
            field_dict["certfr_advisories"] = certfr_advisories
        if cisa_campaigns is not UNSET:
            field_dict["cisa_campaigns"] = cisa_campaigns
        if citations is not UNSET:
            field_dict["citations"] = citations
        if cna_assigner is not UNSET:
            field_dict["cna_assigner"] = cna_assigner
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if countered_techniques is not UNSET:
            field_dict["countered_techniques"] = countered_techniques
        if cve_references is not UNSET:
            field_dict["cve_references"] = cve_references
        if cvss_v2_score is not UNSET:
            field_dict["cvss_v2_score"] = cvss_v2_score
        if cvss_v2_severity is not UNSET:
            field_dict["cvss_v2_severity"] = cvss_v2_severity
        if cvss_v2_vector is not UNSET:
            field_dict["cvss_v2_vector"] = cvss_v2_vector
        if cvss_v3_score is not UNSET:
            field_dict["cvss_v3_score"] = cvss_v3_score
        if cvss_v3_severity is not UNSET:
            field_dict["cvss_v3_severity"] = cvss_v3_severity
        if cvss_v3_vector is not UNSET:
            field_dict["cvss_v3_vector"] = cvss_v3_vector
        if cvss_v3_version is not UNSET:
            field_dict["cvss_v3_version"] = cvss_v3_version
        if cvss_v4_score is not UNSET:
            field_dict["cvss_v4_score"] = cvss_v4_score
        if cvss_v4_severity is not UNSET:
            field_dict["cvss_v4_severity"] = cvss_v4_severity
        if cvss_v4_vector is not UNSET:
            field_dict["cvss_v4_vector"] = cvss_v4_vector
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if d3fend is not UNSET:
            field_dict["d3fend"] = d3fend
        if defense_score is not UNSET:
            field_dict["defense_score"] = defense_score
        if defenses is not UNSET:
            field_dict["defenses"] = defenses
        if detection_strategies is not UNSET:
            field_dict["detection_strategies"] = detection_strategies
        if distro_advisories is not UNSET:
            field_dict["distro_advisories"] = distro_advisories
        if distro_advisories_totals is not UNSET:
            field_dict["distro_advisories_totals"] = distro_advisories_totals
        if distro_advisories_truncated is not UNSET:
            field_dict["distro_advisories_truncated"] = distro_advisories_truncated
        if enrichment is not UNSET:
            field_dict["enrichment"] = enrichment
        if epss is not UNSET:
            field_dict["epss"] = epss
        if epss_percentile is not UNSET:
            field_dict["epss_percentile"] = epss_percentile
        if epss_trend is not UNSET:
            field_dict["epss_trend"] = epss_trend
        if errors is not UNSET:
            field_dict["errors"] = errors
        if evidence_excerpt is not UNSET:
            field_dict["evidence_excerpt"] = evidence_excerpt
        if exploit_maturity is not UNSET:
            field_dict["exploit_maturity"] = exploit_maturity
        if exploits is not UNSET:
            field_dict["exploits"] = exploits
        if extractor is not UNSET:
            field_dict["extractor"] = extractor
        if f3_techniques is not UNSET:
            field_dict["f3_techniques"] = f3_techniques
        if fight_techniques is not UNSET:
            field_dict["fight_techniques"] = fight_techniques
        if fixed_versions is not UNSET:
            field_dict["fixed_versions"] = fixed_versions
        if framework is not UNSET:
            field_dict["framework"] = framework
        if framework_technique is not UNSET:
            field_dict["framework_technique"] = framework_technique
        if galaxy_clusters is not UNSET:
            field_dict["galaxy_clusters"] = galaxy_clusters
        if grade is not UNSET:
            field_dict["grade"] = grade
        if group is not UNSET:
            field_dict["group"] = group
        if group_activity is not UNSET:
            field_dict["group_activity"] = group_activity
        if group_risk is not UNSET:
            field_dict["group_risk"] = group_risk
        if gtfobins_binaries is not UNSET:
            field_dict["gtfobins_binaries"] = gtfobins_binaries
        if gtfobins_binaries_total is not UNSET:
            field_dict["gtfobins_binaries_total"] = gtfobins_binaries_total
        if hijacklibs_entries is not UNSET:
            field_dict["hijacklibs_entries"] = hijacklibs_entries
        if hijacklibs_entries_total is not UNSET:
            field_dict["hijacklibs_entries_total"] = hijacklibs_entries_total
        if ioc_type is not UNSET:
            field_dict["ioc_type"] = ioc_type
        if jvn_advisories is not UNSET:
            field_dict["jvn_advisories"] = jvn_advisories
        if kev is not UNSET:
            field_dict["kev"] = kev
        if kev_due_date is not UNSET:
            field_dict["kev_due_date"] = kev_due_date
        if kev_ransomware is not UNSET:
            field_dict["kev_ransomware"] = kev_ransomware
        if last_modified is not UNSET:
            field_dict["last_modified"] = last_modified
        if lev is not UNSET:
            field_dict["lev"] = lev
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if location is not UNSET:
            field_dict["location"] = location
        if log_sources is not UNSET:
            field_dict["log_sources"] = log_sources
        if lolbas_binaries is not UNSET:
            field_dict["lolbas_binaries"] = lolbas_binaries
        if metasploit_modules is not UNSET:
            field_dict["metasploit_modules"] = metasploit_modules
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if nuclei_templates is not UNSET:
            field_dict["nuclei_templates"] = nuclei_templates
        if osv_ids is not UNSET:
            field_dict["osv_ids"] = osv_ids
        if ot_vendor_advisories is not UNSET:
            field_dict["ot_vendor_advisories"] = ot_vendor_advisories
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if provenance is not UNSET:
            field_dict["provenance"] = provenance
        if published is not UNSET:
            field_dict["published"] = published
        if recent_misp_event_date is not UNSET:
            field_dict["recent_misp_event_date"] = recent_misp_event_date
        if score is not UNSET:
            field_dict["score"] = score
        if score_breakdown is not UNSET:
            field_dict["score_breakdown"] = score_breakdown
        if sector is not UNSET:
            field_dict["sector"] = sector
        if signal_sources is not UNSET:
            field_dict["signal_sources"] = signal_sources
        if software is not UNSET:
            field_dict["software"] = software
        if source_artifact_ids is not UNSET:
            field_dict["source_artifact_ids"] = source_artifact_ids
        if source_location is not UNSET:
            field_dict["source_location"] = source_location
        if ssvc is not UNSET:
            field_dict["ssvc"] = ssvc
        if tactics is not UNSET:
            field_dict["tactics"] = tactics
        if techniques_provenance is not UNSET:
            field_dict["techniques_provenance"] = techniques_provenance
        if threat_actors_origin is not UNSET:
            field_dict["threat_actors_origin"] = threat_actors_origin
        if threat_actors_targeting is not UNSET:
            field_dict["threat_actors_targeting"] = threat_actors_targeting
        if timeline is not UNSET:
            field_dict["timeline"] = timeline
        if vendor_advisories is not UNSET:
            field_dict["vendor_advisories"] = vendor_advisories
        if vuln_status is not UNSET:
            field_dict["vuln_status"] = vuln_status
        if weakness is not UNSET:
            field_dict["weakness"] = weakness

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.activity_summary import ActivitySummary  # noqa: PLC0415
        from ..models.admiralty_grade import AdmiraltyGrade  # noqa: PLC0415
        from ..models.affected_configuration import AffectedConfiguration  # noqa: PLC0415
        from ..models.android_bulletin import AndroidBulletin  # noqa: PLC0415
        from ..models.artifact_enrichment_reference_distro_advisories_totals import (
            ArtifactEnrichmentReferenceDistroAdvisoriesTotals,  # noqa: PLC0415
        )
        from ..models.artifact_enrichment_reference_enrichment_type_0 import (
            ArtifactEnrichmentReferenceEnrichmentType0,  # noqa: PLC0415
        )
        from ..models.artifact_enrichment_reference_score_breakdown import (
            ArtifactEnrichmentReferenceScoreBreakdown,  # noqa: PLC0415
        )
        from ..models.atomic_red_team_test import AtomicRedTeamTest  # noqa: PLC0415
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.capec_detail import CAPECDetail  # noqa: PLC0415
        from ..models.cellular_annotation import CellularAnnotation  # noqa: PLC0415
        from ..models.cellular_core_entry import CellularCoreEntry  # noqa: PLC0415
        from ..models.cert_fr_advisory import CertFRAdvisory  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.citation import Citation  # noqa: PLC0415
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.cwe_detail import CWEDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.defense_triad import DefenseTriad  # noqa: PLC0415
        from ..models.detection_strategy import DetectionStrategy  # noqa: PLC0415
        from ..models.distro_advisory import DistroAdvisory  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.exploit_detail import ExploitDetail  # noqa: PLC0415
        from ..models.f3_technique import F3Technique  # noqa: PLC0415
        from ..models.fight_technique import FightTechnique  # noqa: PLC0415
        from ..models.framework_object_detail import FrameworkObjectDetail  # noqa: PLC0415
        from ..models.galaxy_cluster_detail import GalaxyClusterDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.gtfo_bins_binary import GTFOBinsBinary  # noqa: PLC0415
        from ..models.hijack_libs_entry import HijackLibsEntry  # noqa: PLC0415
        from ..models.jvn_advisory import JVNAdvisory  # noqa: PLC0415
        from ..models.kev_entry import KEVEntry  # noqa: PLC0415
        from ..models.lev_estimate import LEVEstimate  # noqa: PLC0415
        from ..models.location_detail import LocationDetail  # noqa: PLC0415
        from ..models.log_source_group import LogSourceGroup  # noqa: PLC0415
        from ..models.lolbas_binary import LOLBASBinary  # noqa: PLC0415
        from ..models.metasploit_module import MetasploitModule  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.nuclei_template import NucleiTemplate  # noqa: PLC0415
        from ..models.osv_advisory import OSVAdvisory  # noqa: PLC0415
        from ..models.ot_vendor_advisory import OTVendorAdvisory  # noqa: PLC0415
        from ..models.risk_profile import RiskProfile  # noqa: PLC0415
        from ..models.sector_detail import SectorDetail  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.source_stamp import SourceStamp  # noqa: PLC0415
        from ..models.ssvc_decision import SSVCDecision  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.timeline_event import TimelineEvent  # noqa: PLC0415
        from ..models.vendor_advisory import VendorAdvisory  # noqa: PLC0415

        d = dict(src_dict)
        id = d.pop("id")

        type_ = ArtifactEnrichmentReferenceType(d.pop("type"))

        value = d.pop("value")

        def _parse_action(data: object) -> ArtifactEnrichmentReferenceActionType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                action_type_0 = ArtifactEnrichmentReferenceActionType0(data)

                return action_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentReferenceActionType0 | None | Unset, data)

        action = _parse_action(d.pop("action", UNSET))

        _advisories = d.pop("advisories", UNSET)
        advisories: list[OSVAdvisory] | Unset = UNSET
        if _advisories is not UNSET:
            advisories = []
            for advisories_item_data in _advisories:
                advisories_item = OSVAdvisory.from_dict(advisories_item_data)

                advisories.append(advisories_item)

        _affected_configurations = d.pop("affected_configurations", UNSET)
        affected_configurations: list[AffectedConfiguration] | Unset = UNSET
        if _affected_configurations is not UNSET:
            affected_configurations = []
            for affected_configurations_item_data in _affected_configurations:
                affected_configurations_item = AffectedConfiguration.from_dict(affected_configurations_item_data)

                affected_configurations.append(affected_configurations_item)

        affected_configurations_total = d.pop("affected_configurations_total", UNSET)

        def _parse_android_bulletin(data: object) -> AndroidBulletin | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                android_bulletin_type_0 = AndroidBulletin.from_dict(data)

                return android_bulletin_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AndroidBulletin | None | Unset, data)

        android_bulletin = _parse_android_bulletin(d.pop("android_bulletin", UNSET))

        _atlas_mitigations = d.pop("atlas_mitigations", UNSET)
        atlas_mitigations: list[MitigationDetail] | Unset = UNSET
        if _atlas_mitigations is not UNSET:
            atlas_mitigations = []
            for atlas_mitigations_item_data in _atlas_mitigations:
                atlas_mitigations_item = MitigationDetail.from_dict(atlas_mitigations_item_data)

                atlas_mitigations.append(atlas_mitigations_item)

        _atomic_tests = d.pop("atomic_tests", UNSET)
        atomic_tests: list[AtomicRedTeamTest] | Unset = UNSET
        if _atomic_tests is not UNSET:
            atomic_tests = []
            for atomic_tests_item_data in _atomic_tests:
                atomic_tests_item = AtomicRedTeamTest.from_dict(atomic_tests_item_data)

                atomic_tests.append(atomic_tests_item)

        atomic_tests_total = d.pop("atomic_tests_total", UNSET)

        def _parse_attack_pattern(data: object) -> CAPECDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                attack_pattern_type_0 = CAPECDetail.from_dict(data)

                return attack_pattern_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CAPECDetail | None | Unset, data)

        attack_pattern = _parse_attack_pattern(d.pop("attack_pattern", UNSET))

        def _parse_campaign(data: object) -> CampaignDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                campaign_type_0 = CampaignDetail.from_dict(data)

                return campaign_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CampaignDetail | None | Unset, data)

        campaign = _parse_campaign(d.pop("campaign", UNSET))

        _cellular_annotations = d.pop("cellular_annotations", UNSET)
        cellular_annotations: list[CellularAnnotation] | Unset = UNSET
        if _cellular_annotations is not UNSET:
            cellular_annotations = []
            for cellular_annotations_item_data in _cellular_annotations:
                cellular_annotations_item = CellularAnnotation.from_dict(cellular_annotations_item_data)

                cellular_annotations.append(cellular_annotations_item)

        _cellular_core_entries = d.pop("cellular_core_entries", UNSET)
        cellular_core_entries: list[CellularCoreEntry] | Unset = UNSET
        if _cellular_core_entries is not UNSET:
            cellular_core_entries = []
            for cellular_core_entries_item_data in _cellular_core_entries:
                cellular_core_entries_item = CellularCoreEntry.from_dict(cellular_core_entries_item_data)

                cellular_core_entries.append(cellular_core_entries_item)

        _certfr_advisories = d.pop("certfr_advisories", UNSET)
        certfr_advisories: list[CertFRAdvisory] | Unset = UNSET
        if _certfr_advisories is not UNSET:
            certfr_advisories = []
            for certfr_advisories_item_data in _certfr_advisories:
                certfr_advisories_item = CertFRAdvisory.from_dict(certfr_advisories_item_data)

                certfr_advisories.append(certfr_advisories_item)

        _cisa_campaigns = d.pop("cisa_campaigns", UNSET)
        cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
        if _cisa_campaigns is not UNSET:
            cisa_campaigns = []
            for cisa_campaigns_item_data in _cisa_campaigns:
                cisa_campaigns_item = CISACampaignAdvisory.from_dict(cisa_campaigns_item_data)

                cisa_campaigns.append(cisa_campaigns_item)

        _citations = d.pop("citations", UNSET)
        citations: list[Citation] | Unset = UNSET
        if _citations is not UNSET:
            citations = []
            for citations_item_data in _citations:
                citations_item = Citation.from_dict(citations_item_data)

                citations.append(citations_item)

        def _parse_cna_assigner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cna_assigner = _parse_cna_assigner(d.pop("cna_assigner", UNSET))

        def _parse_confidence(data: object) -> ArtifactEnrichmentReferenceConfidenceType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                confidence_type_0 = ArtifactEnrichmentReferenceConfidenceType0(data)

                return confidence_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentReferenceConfidenceType0 | None | Unset, data)

        confidence = _parse_confidence(d.pop("confidence", UNSET))

        countered_techniques = cast(list[str], d.pop("countered_techniques", UNSET))

        _cve_references = d.pop("cve_references", UNSET)
        cve_references: list[CVEReference] | Unset = UNSET
        if _cve_references is not UNSET:
            cve_references = []
            for cve_references_item_data in _cve_references:
                cve_references_item = CVEReference.from_dict(cve_references_item_data)

                cve_references.append(cve_references_item)

        def _parse_cvss_v2_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v2_score = _parse_cvss_v2_score(d.pop("cvss_v2_score", UNSET))

        def _parse_cvss_v2_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v2_severity = _parse_cvss_v2_severity(d.pop("cvss_v2_severity", UNSET))

        def _parse_cvss_v2_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v2_vector = _parse_cvss_v2_vector(d.pop("cvss_v2_vector", UNSET))

        def _parse_cvss_v3_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v3_score = _parse_cvss_v3_score(d.pop("cvss_v3_score", UNSET))

        def _parse_cvss_v3_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_severity = _parse_cvss_v3_severity(d.pop("cvss_v3_severity", UNSET))

        def _parse_cvss_v3_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_vector = _parse_cvss_v3_vector(d.pop("cvss_v3_vector", UNSET))

        def _parse_cvss_v3_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_version = _parse_cvss_v3_version(d.pop("cvss_v3_version", UNSET))

        def _parse_cvss_v4_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v4_score = _parse_cvss_v4_score(d.pop("cvss_v4_score", UNSET))

        def _parse_cvss_v4_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_severity = _parse_cvss_v4_severity(d.pop("cvss_v4_severity", UNSET))

        def _parse_cvss_v4_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_vector = _parse_cvss_v4_vector(d.pop("cvss_v4_vector", UNSET))

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        def _parse_d3fend(data: object) -> D3FENDDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                d3fend_type_0 = D3FENDDetail.from_dict(data)

                return d3fend_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(D3FENDDetail | None | Unset, data)

        d3fend = _parse_d3fend(d.pop("d3fend", UNSET))

        def _parse_defense_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        defense_score = _parse_defense_score(d.pop("defense_score", UNSET))

        _defenses = d.pop("defenses", UNSET)
        defenses: list[DefenseTriad] | Unset = UNSET
        if _defenses is not UNSET:
            defenses = []
            for defenses_item_data in _defenses:
                defenses_item = DefenseTriad.from_dict(defenses_item_data)

                defenses.append(defenses_item)

        _detection_strategies = d.pop("detection_strategies", UNSET)
        detection_strategies: list[DetectionStrategy] | Unset = UNSET
        if _detection_strategies is not UNSET:
            detection_strategies = []
            for detection_strategies_item_data in _detection_strategies:
                detection_strategies_item = DetectionStrategy.from_dict(detection_strategies_item_data)

                detection_strategies.append(detection_strategies_item)

        _distro_advisories = d.pop("distro_advisories", UNSET)
        distro_advisories: list[DistroAdvisory] | Unset = UNSET
        if _distro_advisories is not UNSET:
            distro_advisories = []
            for distro_advisories_item_data in _distro_advisories:
                distro_advisories_item = DistroAdvisory.from_dict(distro_advisories_item_data)

                distro_advisories.append(distro_advisories_item)

        _distro_advisories_totals = d.pop("distro_advisories_totals", UNSET)
        distro_advisories_totals: ArtifactEnrichmentReferenceDistroAdvisoriesTotals | Unset
        if isinstance(_distro_advisories_totals, Unset):
            distro_advisories_totals = UNSET
        else:
            distro_advisories_totals = ArtifactEnrichmentReferenceDistroAdvisoriesTotals.from_dict(
                _distro_advisories_totals
            )

        distro_advisories_truncated = d.pop("distro_advisories_truncated", UNSET)

        def _parse_enrichment(data: object) -> ArtifactEnrichmentReferenceEnrichmentType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                enrichment_type_0 = ArtifactEnrichmentReferenceEnrichmentType0.from_dict(data)

                return enrichment_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentReferenceEnrichmentType0 | None | Unset, data)

        enrichment = _parse_enrichment(d.pop("enrichment", UNSET))

        def _parse_epss(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss = _parse_epss(d.pop("epss", UNSET))

        def _parse_epss_percentile(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_percentile = _parse_epss_percentile(d.pop("epss_percentile", UNSET))

        def _parse_epss_trend(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        epss_trend = _parse_epss_trend(d.pop("epss_trend", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_evidence_excerpt(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        evidence_excerpt = _parse_evidence_excerpt(d.pop("evidence_excerpt", UNSET))

        def _parse_exploit_maturity(data: object) -> ArtifactEnrichmentReferenceExploitMaturityType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                exploit_maturity_type_0 = ArtifactEnrichmentReferenceExploitMaturityType0(data)

                return exploit_maturity_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentReferenceExploitMaturityType0 | None | Unset, data)

        exploit_maturity = _parse_exploit_maturity(d.pop("exploit_maturity", UNSET))

        _exploits = d.pop("exploits", UNSET)
        exploits: list[ExploitDetail] | Unset = UNSET
        if _exploits is not UNSET:
            exploits = []
            for exploits_item_data in _exploits:
                exploits_item = ExploitDetail.from_dict(exploits_item_data)

                exploits.append(exploits_item)

        def _parse_extractor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extractor = _parse_extractor(d.pop("extractor", UNSET))

        _f3_techniques = d.pop("f3_techniques", UNSET)
        f3_techniques: list[F3Technique] | Unset = UNSET
        if _f3_techniques is not UNSET:
            f3_techniques = []
            for f3_techniques_item_data in _f3_techniques:
                f3_techniques_item = F3Technique.from_dict(f3_techniques_item_data)

                f3_techniques.append(f3_techniques_item)

        _fight_techniques = d.pop("fight_techniques", UNSET)
        fight_techniques: list[FightTechnique] | Unset = UNSET
        if _fight_techniques is not UNSET:
            fight_techniques = []
            for fight_techniques_item_data in _fight_techniques:
                fight_techniques_item = FightTechnique.from_dict(fight_techniques_item_data)

                fight_techniques.append(fight_techniques_item)

        fixed_versions = cast(list[str], d.pop("fixed_versions", UNSET))

        def _parse_framework(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        framework = _parse_framework(d.pop("framework", UNSET))

        def _parse_framework_technique(data: object) -> FrameworkObjectDetail | None | TechniqueDetail | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                framework_technique_type_0 = TechniqueDetail.from_dict(data)

                return framework_technique_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                framework_technique_type_1 = FrameworkObjectDetail.from_dict(data)

                return framework_technique_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FrameworkObjectDetail | None | TechniqueDetail | Unset, data)

        framework_technique = _parse_framework_technique(d.pop("framework_technique", UNSET))

        _galaxy_clusters = d.pop("galaxy_clusters", UNSET)
        galaxy_clusters: list[GalaxyClusterDetail] | Unset = UNSET
        if _galaxy_clusters is not UNSET:
            galaxy_clusters = []
            for galaxy_clusters_item_data in _galaxy_clusters:
                galaxy_clusters_item = GalaxyClusterDetail.from_dict(galaxy_clusters_item_data)

                galaxy_clusters.append(galaxy_clusters_item)

        def _parse_grade(data: object) -> AdmiraltyGrade | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                grade_type_0 = AdmiraltyGrade.from_dict(data)

                return grade_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AdmiraltyGrade | None | Unset, data)

        grade = _parse_grade(d.pop("grade", UNSET))

        def _parse_group(data: object) -> GroupDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                group_type_0 = GroupDetail.from_dict(data)

                return group_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GroupDetail | None | Unset, data)

        group = _parse_group(d.pop("group", UNSET))

        def _parse_group_activity(data: object) -> ActivitySummary | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                group_activity_type_0 = ActivitySummary.from_dict(data)

                return group_activity_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ActivitySummary | None | Unset, data)

        group_activity = _parse_group_activity(d.pop("group_activity", UNSET))

        def _parse_group_risk(data: object) -> None | RiskProfile | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                group_risk_type_0 = RiskProfile.from_dict(data)

                return group_risk_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RiskProfile | Unset, data)

        group_risk = _parse_group_risk(d.pop("group_risk", UNSET))

        _gtfobins_binaries = d.pop("gtfobins_binaries", UNSET)
        gtfobins_binaries: list[GTFOBinsBinary] | Unset = UNSET
        if _gtfobins_binaries is not UNSET:
            gtfobins_binaries = []
            for gtfobins_binaries_item_data in _gtfobins_binaries:
                gtfobins_binaries_item = GTFOBinsBinary.from_dict(gtfobins_binaries_item_data)

                gtfobins_binaries.append(gtfobins_binaries_item)

        gtfobins_binaries_total = d.pop("gtfobins_binaries_total", UNSET)

        _hijacklibs_entries = d.pop("hijacklibs_entries", UNSET)
        hijacklibs_entries: list[HijackLibsEntry] | Unset = UNSET
        if _hijacklibs_entries is not UNSET:
            hijacklibs_entries = []
            for hijacklibs_entries_item_data in _hijacklibs_entries:
                hijacklibs_entries_item = HijackLibsEntry.from_dict(hijacklibs_entries_item_data)

                hijacklibs_entries.append(hijacklibs_entries_item)

        hijacklibs_entries_total = d.pop("hijacklibs_entries_total", UNSET)

        def _parse_ioc_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ioc_type = _parse_ioc_type(d.pop("ioc_type", UNSET))

        _jvn_advisories = d.pop("jvn_advisories", UNSET)
        jvn_advisories: list[JVNAdvisory] | Unset = UNSET
        if _jvn_advisories is not UNSET:
            jvn_advisories = []
            for jvn_advisories_item_data in _jvn_advisories:
                jvn_advisories_item = JVNAdvisory.from_dict(jvn_advisories_item_data)

                jvn_advisories.append(jvn_advisories_item)

        def _parse_kev(data: object) -> KEVEntry | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                kev_type_0 = KEVEntry.from_dict(data)

                return kev_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(KEVEntry | None | Unset, data)

        kev = _parse_kev(d.pop("kev", UNSET))

        def _parse_kev_due_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_due_date = _parse_kev_due_date(d.pop("kev_due_date", UNSET))

        kev_ransomware = d.pop("kev_ransomware", UNSET)

        def _parse_last_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_modified = _parse_last_modified(d.pop("last_modified", UNSET))

        def _parse_lev(data: object) -> LEVEstimate | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                lev_type_0 = LEVEstimate.from_dict(data)

                return lev_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(LEVEstimate | None | Unset, data)

        lev = _parse_lev(d.pop("lev", UNSET))

        def _parse_likelihood(data: object) -> ArtifactEnrichmentReferenceLikelihoodType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                likelihood_type_0 = ArtifactEnrichmentReferenceLikelihoodType0(data)

                return likelihood_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentReferenceLikelihoodType0 | None | Unset, data)

        likelihood = _parse_likelihood(d.pop("likelihood", UNSET))

        def _parse_location(data: object) -> LocationDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                location_type_0 = LocationDetail.from_dict(data)

                return location_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(LocationDetail | None | Unset, data)

        location = _parse_location(d.pop("location", UNSET))

        _log_sources = d.pop("log_sources", UNSET)
        log_sources: list[LogSourceGroup] | Unset = UNSET
        if _log_sources is not UNSET:
            log_sources = []
            for log_sources_item_data in _log_sources:
                log_sources_item = LogSourceGroup.from_dict(log_sources_item_data)

                log_sources.append(log_sources_item)

        _lolbas_binaries = d.pop("lolbas_binaries", UNSET)
        lolbas_binaries: list[LOLBASBinary] | Unset = UNSET
        if _lolbas_binaries is not UNSET:
            lolbas_binaries = []
            for lolbas_binaries_item_data in _lolbas_binaries:
                lolbas_binaries_item = LOLBASBinary.from_dict(lolbas_binaries_item_data)

                lolbas_binaries.append(lolbas_binaries_item)

        _metasploit_modules = d.pop("metasploit_modules", UNSET)
        metasploit_modules: list[MetasploitModule] | Unset = UNSET
        if _metasploit_modules is not UNSET:
            metasploit_modules = []
            for metasploit_modules_item_data in _metasploit_modules:
                metasploit_modules_item = MetasploitModule.from_dict(metasploit_modules_item_data)

                metasploit_modules.append(metasploit_modules_item)

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        _nuclei_templates = d.pop("nuclei_templates", UNSET)
        nuclei_templates: list[NucleiTemplate] | Unset = UNSET
        if _nuclei_templates is not UNSET:
            nuclei_templates = []
            for nuclei_templates_item_data in _nuclei_templates:
                nuclei_templates_item = NucleiTemplate.from_dict(nuclei_templates_item_data)

                nuclei_templates.append(nuclei_templates_item)

        osv_ids = cast(list[str], d.pop("osv_ids", UNSET))

        _ot_vendor_advisories = d.pop("ot_vendor_advisories", UNSET)
        ot_vendor_advisories: list[OTVendorAdvisory] | Unset = UNSET
        if _ot_vendor_advisories is not UNSET:
            ot_vendor_advisories = []
            for ot_vendor_advisories_item_data in _ot_vendor_advisories:
                ot_vendor_advisories_item = OTVendorAdvisory.from_dict(ot_vendor_advisories_item_data)

                ot_vendor_advisories.append(ot_vendor_advisories_item)

        platforms = cast(list[str], d.pop("platforms", UNSET))

        _provenance = d.pop("provenance", UNSET)
        provenance: list[SourceStamp] | Unset = UNSET
        if _provenance is not UNSET:
            provenance = []
            for provenance_item_data in _provenance:
                provenance_item = SourceStamp.from_dict(provenance_item_data)

                provenance.append(provenance_item)

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        def _parse_recent_misp_event_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        recent_misp_event_date = _parse_recent_misp_event_date(d.pop("recent_misp_event_date", UNSET))

        def _parse_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        score = _parse_score(d.pop("score", UNSET))

        _score_breakdown = d.pop("score_breakdown", UNSET)
        score_breakdown: ArtifactEnrichmentReferenceScoreBreakdown | Unset
        if isinstance(_score_breakdown, Unset):
            score_breakdown = UNSET
        else:
            score_breakdown = ArtifactEnrichmentReferenceScoreBreakdown.from_dict(_score_breakdown)

        def _parse_sector(data: object) -> None | SectorDetail | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                sector_type_0 = SectorDetail.from_dict(data)

                return sector_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SectorDetail | Unset, data)

        sector = _parse_sector(d.pop("sector", UNSET))

        signal_sources = cast(list[str], d.pop("signal_sources", UNSET))

        def _parse_software(data: object) -> None | SoftwareDetail | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                software_type_0 = SoftwareDetail.from_dict(data)

                return software_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SoftwareDetail | Unset, data)

        software = _parse_software(d.pop("software", UNSET))

        source_artifact_ids = cast(list[str], d.pop("source_artifact_ids", UNSET))

        def _parse_source_location(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_location = _parse_source_location(d.pop("source_location", UNSET))

        def _parse_ssvc(data: object) -> None | SSVCDecision | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                ssvc_type_0 = SSVCDecision.from_dict(data)

                return ssvc_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SSVCDecision | Unset, data)

        ssvc = _parse_ssvc(d.pop("ssvc", UNSET))

        tactics = cast(list[str], d.pop("tactics", UNSET))

        def _parse_techniques_provenance(
            data: object,
        ) -> ArtifactEnrichmentReferenceTechniquesProvenanceType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                techniques_provenance_type_0 = ArtifactEnrichmentReferenceTechniquesProvenanceType0(data)

                return techniques_provenance_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentReferenceTechniquesProvenanceType0 | None | Unset, data)

        techniques_provenance = _parse_techniques_provenance(d.pop("techniques_provenance", UNSET))

        threat_actors_origin = cast(list[str], d.pop("threat_actors_origin", UNSET))

        threat_actors_targeting = cast(list[str], d.pop("threat_actors_targeting", UNSET))

        _timeline = d.pop("timeline", UNSET)
        timeline: list[TimelineEvent] | Unset = UNSET
        if _timeline is not UNSET:
            timeline = []
            for timeline_item_data in _timeline:
                timeline_item = TimelineEvent.from_dict(timeline_item_data)

                timeline.append(timeline_item)

        _vendor_advisories = d.pop("vendor_advisories", UNSET)
        vendor_advisories: list[VendorAdvisory] | Unset = UNSET
        if _vendor_advisories is not UNSET:
            vendor_advisories = []
            for vendor_advisories_item_data in _vendor_advisories:
                vendor_advisories_item = VendorAdvisory.from_dict(vendor_advisories_item_data)

                vendor_advisories.append(vendor_advisories_item)

        def _parse_vuln_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vuln_status = _parse_vuln_status(d.pop("vuln_status", UNSET))

        def _parse_weakness(data: object) -> CWEDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                weakness_type_0 = CWEDetail.from_dict(data)

                return weakness_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CWEDetail | None | Unset, data)

        weakness = _parse_weakness(d.pop("weakness", UNSET))

        artifact_enrichment_reference = cls(
            id=id,
            type_=type_,
            value=value,
            action=action,
            advisories=advisories,
            affected_configurations=affected_configurations,
            affected_configurations_total=affected_configurations_total,
            android_bulletin=android_bulletin,
            atlas_mitigations=atlas_mitigations,
            atomic_tests=atomic_tests,
            atomic_tests_total=atomic_tests_total,
            attack_pattern=attack_pattern,
            campaign=campaign,
            cellular_annotations=cellular_annotations,
            cellular_core_entries=cellular_core_entries,
            certfr_advisories=certfr_advisories,
            cisa_campaigns=cisa_campaigns,
            citations=citations,
            cna_assigner=cna_assigner,
            confidence=confidence,
            countered_techniques=countered_techniques,
            cve_references=cve_references,
            cvss_v2_score=cvss_v2_score,
            cvss_v2_severity=cvss_v2_severity,
            cvss_v2_vector=cvss_v2_vector,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_severity=cvss_v3_severity,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v3_version=cvss_v3_version,
            cvss_v4_score=cvss_v4_score,
            cvss_v4_severity=cvss_v4_severity,
            cvss_v4_vector=cvss_v4_vector,
            cwe_ids=cwe_ids,
            d3fend=d3fend,
            defense_score=defense_score,
            defenses=defenses,
            detection_strategies=detection_strategies,
            distro_advisories=distro_advisories,
            distro_advisories_totals=distro_advisories_totals,
            distro_advisories_truncated=distro_advisories_truncated,
            enrichment=enrichment,
            epss=epss,
            epss_percentile=epss_percentile,
            epss_trend=epss_trend,
            errors=errors,
            evidence_excerpt=evidence_excerpt,
            exploit_maturity=exploit_maturity,
            exploits=exploits,
            extractor=extractor,
            f3_techniques=f3_techniques,
            fight_techniques=fight_techniques,
            fixed_versions=fixed_versions,
            framework=framework,
            framework_technique=framework_technique,
            galaxy_clusters=galaxy_clusters,
            grade=grade,
            group=group,
            group_activity=group_activity,
            group_risk=group_risk,
            gtfobins_binaries=gtfobins_binaries,
            gtfobins_binaries_total=gtfobins_binaries_total,
            hijacklibs_entries=hijacklibs_entries,
            hijacklibs_entries_total=hijacklibs_entries_total,
            ioc_type=ioc_type,
            jvn_advisories=jvn_advisories,
            kev=kev,
            kev_due_date=kev_due_date,
            kev_ransomware=kev_ransomware,
            last_modified=last_modified,
            lev=lev,
            likelihood=likelihood,
            location=location,
            log_sources=log_sources,
            lolbas_binaries=lolbas_binaries,
            metasploit_modules=metasploit_modules,
            nist_controls=nist_controls,
            nuclei_templates=nuclei_templates,
            osv_ids=osv_ids,
            ot_vendor_advisories=ot_vendor_advisories,
            platforms=platforms,
            provenance=provenance,
            published=published,
            recent_misp_event_date=recent_misp_event_date,
            score=score,
            score_breakdown=score_breakdown,
            sector=sector,
            signal_sources=signal_sources,
            software=software,
            source_artifact_ids=source_artifact_ids,
            source_location=source_location,
            ssvc=ssvc,
            tactics=tactics,
            techniques_provenance=techniques_provenance,
            threat_actors_origin=threat_actors_origin,
            threat_actors_targeting=threat_actors_targeting,
            timeline=timeline,
            vendor_advisories=vendor_advisories,
            vuln_status=vuln_status,
            weakness=weakness,
        )

        artifact_enrichment_reference.additional_properties = d
        return artifact_enrichment_reference

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
