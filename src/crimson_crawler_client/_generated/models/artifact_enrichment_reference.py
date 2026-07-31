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
    from ..models.admiralty_grade import AdmiraltyGrade
    from ..models.artifact_enrichment_reference_enrichment_type_0 import ArtifactEnrichmentReferenceEnrichmentType0
    from ..models.artifact_enrichment_reference_score_breakdown import ArtifactEnrichmentReferenceScoreBreakdown
    from ..models.citation import Citation
    from ..models.defense_triad import DefenseTriad
    from ..models.error_detail import ErrorDetail
    from ..models.exploit_detail import ExploitDetail
    from ..models.galaxy_cluster_detail import GalaxyClusterDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.osv_advisory import OSVAdvisory
    from ..models.ssvc_decision import SSVCDecision
    from ..models.timeline_event import TimelineEvent


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
            citations (list[Citation] | Unset): Per-reference graded citations
            cna_assigner (None | str | Unset): Authoritative CNA (CVE Numbering Authority) that assigned the CVE — e.g.
                'Cisco PSIRT', 'MITRE'. Sourced from the CVE bundle's STIX created_by_ref/assigner. CVE refs only.
            confidence (ArtifactEnrichmentReferenceConfidenceType0 | None | Unset): Analytic confidence (multi-source
                corroboration)
            cvss_score (float | None | Unset): CVSS base score
            cvss_severity (None | str | Unset): CVSS severity
            defense_score (float | None | Unset): 0-100 deterministic DEFENSE-readiness score for this reference — how well
                its ATT&CK techniques are covered by detections / mitigations / D3FEND counters (detection weighted highest).
                The symmetric counterpart to ``score``. Null when the reference has no mapped ATT&CK techniques (coverage can't
                be assessed).
            defenses (list[DefenseTriad] | Unset): Per-technique detect/mitigate/counter triads
            enrichment (ArtifactEnrichmentReferenceEnrichmentType0 | None | Unset): Curated per-reference details returned
                only with `include=['enrichment']`. Contains descriptive and relationship context that has no dedicated top-
                level field. CVSS, EPSS, and KEV values remain in their typed top-level fields; raw source payloads are not
                returned.
            epss (float | None | Unset): EPSS probability (0-1)
            epss_cohort_percentile (float | None | Unset): EPSS cohort percentile (0-1) — where this CVE sits within its
                publish-month cohort. Higher = more exploited relative to peers.
            epss_trend (None | str | Unset): EPSS velocity trend (rising/stable/falling/…)
            errors (list[ErrorDetail] | Unset): Per-reference partial-failure details
            evidence_excerpt (None | str | Unset): ±120 chars of the SOURCE DOCUMENT around this reference's first
                occurrence — the analyst's own words. The enricher deliberately does not model incident-specific uncertainty
                ('probed but not confirmed'); this carries that prose context alongside the deterministic verdict so a human can
                weigh both. Best-effort: null when the value never appears verbatim (parsed CPEs, file-format extractors).
            exploit_maturity (ArtifactEnrichmentReferenceExploitMaturityType0 | None | Unset): Exploit maturity (cvss-bt
                priority tree: KEV/active→attacked, PoC→poc, …)
            exploits (list[ExploitDetail] | Unset): Authoritative exploit objects from the authoritative KEV exploit feed
                (real exploit evidence — type + references + STIX id). CVE refs only. Stronger signal than the PoC count.
            extractor (None | str | Unset): Which extractor produced the ref (regex | nmap_xml | csv | …)
            framework (None | str | Unset): ATT&CK framework for technique refs (enterprise | ics) — disambiguates the
                shared T#### id space
            galaxy_clusters (list[GalaxyClusterDetail] | Unset): Full MISP Galaxy cluster profiles referenced by this
                reference's MISP attributes — threat-actor / malware / tool / technique clusters with aliases, source,
                description, and relations. IOC refs only.
            grade (AdmiraltyGrade | None | Unset): Deterministic NATO Admiralty grade for this reference
            ioc_type (None | str | Unset): Indicator subtype for IOC refs (ip-dst | domain | url | hash)
            kev_due_date (None | str | Unset): CISA KEV remediation deadline, when listed
            kev_ransomware (bool | Unset): Linked to a known ransomware campaign (CISA KEV) Default: False.
            likelihood (ArtifactEnrichmentReferenceLikelihoodType0 | None | Unset): ICD-203 Words-of-Estimative-Probability
                band (derived from the score)
            nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate techniques mapped
                to this reference. Each entry identifies the control, family, ATT&CK technique, and mapping rationale.
            recent_misp_event_date (None | str | Unset): Most recent MISP event date this reference appears in (ISO date).
                For IOCs, signals recency of last sighting; older dates indicate stale corroboration.
            score (float | None | Unset): 0-100 deterministic priority (attack) score
            score_breakdown (ArtifactEnrichmentReferenceScoreBreakdown | Unset): Per-signal contributions to the score
            signal_sources (list[str] | Unset): Intelligence sources that contributed a signal
            source_location (None | str | Unset): Where in the artifact the ref was found (line/row/page)
            ssvc (None | SSVCDecision | Unset): Deterministic SSVC decision (CVE/product lane)
            techniques_provenance (ArtifactEnrichmentReferenceTechniquesProvenanceType0 | None | Unset): Precision class for
                linked ATT&CK techniques on this reference: `cve_specific` for vulnerability-specific evidence, `cwe_class` for
                broad weakness-class evidence, and `heuristic` for indirect evidence.
            timeline (list[TimelineEvent] | Unset): Chronological narrative for this reference — disclosure, KEV listing,
                KEV deadline, first PoC, and EPSS-trajectory inflection (when derivable from the score timeseries). All events
                are pure derivations from already-fetched fields; no invented signals.
    """

    id: str
    type_: ArtifactEnrichmentReferenceType
    value: str
    action: ArtifactEnrichmentReferenceActionType0 | None | Unset = UNSET
    advisories: list[OSVAdvisory] | Unset = UNSET
    citations: list[Citation] | Unset = UNSET
    cna_assigner: None | str | Unset = UNSET
    confidence: ArtifactEnrichmentReferenceConfidenceType0 | None | Unset = UNSET
    cvss_score: float | None | Unset = UNSET
    cvss_severity: None | str | Unset = UNSET
    defense_score: float | None | Unset = UNSET
    defenses: list[DefenseTriad] | Unset = UNSET
    enrichment: ArtifactEnrichmentReferenceEnrichmentType0 | None | Unset = UNSET
    epss: float | None | Unset = UNSET
    epss_cohort_percentile: float | None | Unset = UNSET
    epss_trend: None | str | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    evidence_excerpt: None | str | Unset = UNSET
    exploit_maturity: ArtifactEnrichmentReferenceExploitMaturityType0 | None | Unset = UNSET
    exploits: list[ExploitDetail] | Unset = UNSET
    extractor: None | str | Unset = UNSET
    framework: None | str | Unset = UNSET
    galaxy_clusters: list[GalaxyClusterDetail] | Unset = UNSET
    grade: AdmiraltyGrade | None | Unset = UNSET
    ioc_type: None | str | Unset = UNSET
    kev_due_date: None | str | Unset = UNSET
    kev_ransomware: bool | Unset = False
    likelihood: ArtifactEnrichmentReferenceLikelihoodType0 | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    recent_misp_event_date: None | str | Unset = UNSET
    score: float | None | Unset = UNSET
    score_breakdown: ArtifactEnrichmentReferenceScoreBreakdown | Unset = UNSET
    signal_sources: list[str] | Unset = UNSET
    source_location: None | str | Unset = UNSET
    ssvc: None | SSVCDecision | Unset = UNSET
    techniques_provenance: ArtifactEnrichmentReferenceTechniquesProvenanceType0 | None | Unset = UNSET
    timeline: list[TimelineEvent] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.admiralty_grade import AdmiraltyGrade
        from ..models.artifact_enrichment_reference_enrichment_type_0 import ArtifactEnrichmentReferenceEnrichmentType0
        from ..models.artifact_enrichment_reference_score_breakdown import ArtifactEnrichmentReferenceScoreBreakdown
        from ..models.citation import Citation
        from ..models.defense_triad import DefenseTriad
        from ..models.error_detail import ErrorDetail
        from ..models.exploit_detail import ExploitDetail
        from ..models.galaxy_cluster_detail import GalaxyClusterDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.osv_advisory import OSVAdvisory
        from ..models.ssvc_decision import SSVCDecision
        from ..models.timeline_event import TimelineEvent

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

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        cvss_severity: None | str | Unset
        if isinstance(self.cvss_severity, Unset):
            cvss_severity = UNSET
        else:
            cvss_severity = self.cvss_severity

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

        epss_cohort_percentile: float | None | Unset
        if isinstance(self.epss_cohort_percentile, Unset):
            epss_cohort_percentile = UNSET
        else:
            epss_cohort_percentile = self.epss_cohort_percentile

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

        framework: None | str | Unset
        if isinstance(self.framework, Unset):
            framework = UNSET
        else:
            framework = self.framework

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

        ioc_type: None | str | Unset
        if isinstance(self.ioc_type, Unset):
            ioc_type = UNSET
        else:
            ioc_type = self.ioc_type

        kev_due_date: None | str | Unset
        if isinstance(self.kev_due_date, Unset):
            kev_due_date = UNSET
        else:
            kev_due_date = self.kev_due_date

        kev_ransomware = self.kev_ransomware

        likelihood: None | str | Unset
        if isinstance(self.likelihood, Unset):
            likelihood = UNSET
        elif isinstance(self.likelihood, ArtifactEnrichmentReferenceLikelihoodType0):
            likelihood = self.likelihood.value
        else:
            likelihood = self.likelihood

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

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

        signal_sources: list[str] | Unset = UNSET
        if not isinstance(self.signal_sources, Unset):
            signal_sources = self.signal_sources

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

        techniques_provenance: None | str | Unset
        if isinstance(self.techniques_provenance, Unset):
            techniques_provenance = UNSET
        elif isinstance(self.techniques_provenance, ArtifactEnrichmentReferenceTechniquesProvenanceType0):
            techniques_provenance = self.techniques_provenance.value
        else:
            techniques_provenance = self.techniques_provenance

        timeline: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.timeline, Unset):
            timeline = []
            for timeline_item_data in self.timeline:
                timeline_item = timeline_item_data.to_dict()
                timeline.append(timeline_item)

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
        if citations is not UNSET:
            field_dict["citations"] = citations
        if cna_assigner is not UNSET:
            field_dict["cna_assigner"] = cna_assigner
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if cvss_severity is not UNSET:
            field_dict["cvss_severity"] = cvss_severity
        if defense_score is not UNSET:
            field_dict["defense_score"] = defense_score
        if defenses is not UNSET:
            field_dict["defenses"] = defenses
        if enrichment is not UNSET:
            field_dict["enrichment"] = enrichment
        if epss is not UNSET:
            field_dict["epss"] = epss
        if epss_cohort_percentile is not UNSET:
            field_dict["epss_cohort_percentile"] = epss_cohort_percentile
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
        if framework is not UNSET:
            field_dict["framework"] = framework
        if galaxy_clusters is not UNSET:
            field_dict["galaxy_clusters"] = galaxy_clusters
        if grade is not UNSET:
            field_dict["grade"] = grade
        if ioc_type is not UNSET:
            field_dict["ioc_type"] = ioc_type
        if kev_due_date is not UNSET:
            field_dict["kev_due_date"] = kev_due_date
        if kev_ransomware is not UNSET:
            field_dict["kev_ransomware"] = kev_ransomware
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if recent_misp_event_date is not UNSET:
            field_dict["recent_misp_event_date"] = recent_misp_event_date
        if score is not UNSET:
            field_dict["score"] = score
        if score_breakdown is not UNSET:
            field_dict["score_breakdown"] = score_breakdown
        if signal_sources is not UNSET:
            field_dict["signal_sources"] = signal_sources
        if source_location is not UNSET:
            field_dict["source_location"] = source_location
        if ssvc is not UNSET:
            field_dict["ssvc"] = ssvc
        if techniques_provenance is not UNSET:
            field_dict["techniques_provenance"] = techniques_provenance
        if timeline is not UNSET:
            field_dict["timeline"] = timeline

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admiralty_grade import AdmiraltyGrade
        from ..models.artifact_enrichment_reference_enrichment_type_0 import ArtifactEnrichmentReferenceEnrichmentType0
        from ..models.artifact_enrichment_reference_score_breakdown import ArtifactEnrichmentReferenceScoreBreakdown
        from ..models.citation import Citation
        from ..models.defense_triad import DefenseTriad
        from ..models.error_detail import ErrorDetail
        from ..models.exploit_detail import ExploitDetail
        from ..models.galaxy_cluster_detail import GalaxyClusterDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.osv_advisory import OSVAdvisory
        from ..models.ssvc_decision import SSVCDecision
        from ..models.timeline_event import TimelineEvent

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

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_cvss_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_severity = _parse_cvss_severity(d.pop("cvss_severity", UNSET))

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

        def _parse_epss_cohort_percentile(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_cohort_percentile = _parse_epss_cohort_percentile(d.pop("epss_cohort_percentile", UNSET))

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

        def _parse_framework(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        framework = _parse_framework(d.pop("framework", UNSET))

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

        def _parse_ioc_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ioc_type = _parse_ioc_type(d.pop("ioc_type", UNSET))

        def _parse_kev_due_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_due_date = _parse_kev_due_date(d.pop("kev_due_date", UNSET))

        kev_ransomware = d.pop("kev_ransomware", UNSET)

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

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

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

        signal_sources = cast(list[str], d.pop("signal_sources", UNSET))

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

        _timeline = d.pop("timeline", UNSET)
        timeline: list[TimelineEvent] | Unset = UNSET
        if _timeline is not UNSET:
            timeline = []
            for timeline_item_data in _timeline:
                timeline_item = TimelineEvent.from_dict(timeline_item_data)

                timeline.append(timeline_item)

        artifact_enrichment_reference = cls(
            id=id,
            type_=type_,
            value=value,
            action=action,
            advisories=advisories,
            citations=citations,
            cna_assigner=cna_assigner,
            confidence=confidence,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            defense_score=defense_score,
            defenses=defenses,
            enrichment=enrichment,
            epss=epss,
            epss_cohort_percentile=epss_cohort_percentile,
            epss_trend=epss_trend,
            errors=errors,
            evidence_excerpt=evidence_excerpt,
            exploit_maturity=exploit_maturity,
            exploits=exploits,
            extractor=extractor,
            framework=framework,
            galaxy_clusters=galaxy_clusters,
            grade=grade,
            ioc_type=ioc_type,
            kev_due_date=kev_due_date,
            kev_ransomware=kev_ransomware,
            likelihood=likelihood,
            nist_controls=nist_controls,
            recent_misp_event_date=recent_misp_event_date,
            score=score,
            score_breakdown=score_breakdown,
            signal_sources=signal_sources,
            source_location=source_location,
            ssvc=ssvc,
            techniques_provenance=techniques_provenance,
            timeline=timeline,
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
