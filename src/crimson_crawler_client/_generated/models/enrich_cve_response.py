from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.enrich_cve_response_techniques_provenance_type_0 import EnrichCVEResponseTechniquesProvenanceType0
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.affected_product import AffectedProduct
    from ..models.campaign_detail import CampaignDetail
    from ..models.capec_detail import CAPECDetail
    from ..models.confidence import Confidence
    from ..models.cve_detail import CVEDetail
    from ..models.cve_mini_detail import CVEMiniDetail
    from ..models.cwe_detail import CWEDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.enrich_cve_response_navigator_type_0 import EnrichCVEResponseNavigatorType0
    from ..models.epss_score import EPSSScore
    from ..models.epss_velocity import EPSSVelocity
    from ..models.error_detail import ErrorDetail
    from ..models.exploit_detail import ExploitDetail
    from ..models.group_detail import GroupDetail
    from ..models.inferred_chain_candidate import InferredChainCandidate
    from ..models.kev_entry import KEVEntry
    from ..models.knowledgebase_result import KnowledgebaseResult
    from ..models.misp_attribute import MISPAttribute
    from ..models.mitigation_detail import MitigationDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.osv_advisory import OSVAdvisory
    from ..models.po_c_entry import PoCEntry
    from ..models.po_c_source_entry import PoCSourceEntry
    from ..models.sector_context import SectorContext
    from ..models.software_detail import SoftwareDetail
    from ..models.ssvc_decision import SSVCDecision
    from ..models.technique_detail import TechniqueDetail
    from ..models.threat_prediction import ThreatPrediction
    from ..models.timeline_entry import TimelineEntry
    from ..models.web_result import WebResult


T = TypeVar("T", bound="EnrichCVEResponse")


@_attrs_define
class EnrichCVEResponse:
    """Response from `/v1/enrich/cve`.

    Returns severity, exploit signals, adversary techniques, and an optional AI summary. Use `include`
    to control depth. When published mappings yield no techniques, check `likely_tactics` or request
    `inferred_chain` to receive low-confidence analyst hints in `inferred_chain_candidates`.

        Attributes:
            affected_products (list[AffectedProduct] | Unset): Confirmed vulnerable software with vendor, product, version,
                and CPE string
            attack_patterns (list[CAPECDetail] | Unset): Attack patterns describing how the weakness is exploited (CAPEC)
            campaigns (list[CampaignDetail] | Unset): Threat campaigns that used the linked techniques
            confidence (Confidence | None | Unset): Enrichment completeness indicator: data_quality bucket
                (`none`/`low`/`moderate`/`high`), per-source response counts, and corroboration adjustments. The `none` bucket
                is the canonical signal that the enrichment lookup found nothing — distinguish it from `low`. See the
                `Confidence` model for field-level semantics.
            cve (CVEDetail | None | Unset): Core vulnerability details and CVSS scoring
            defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
                techniques
            detections (list[DetectionDetail] | Unset): Detection data sources and components for the linked techniques
            epss (EPSSScore | None | Unset): Exploit probability score
            epss_velocity (EPSSVelocity | None | Unset): EPSS score trend over the last 7 and 30 days with direction,
                acceleration, and optional inflection flag. Populated when `include=['timeline']` produced data. `null`
                otherwise.
            errors (list[ErrorDetail] | Unset): Partial failure details - check this array for incomplete enrichment
            exploits (list[ExploitDetail] | Unset): Authoritative exploit objects linked to this CVE (authoritative KEV
                exploit feed). Returned when include=['exploits']. Real exploit evidence (type + references), not a heuristic
                guess.
            groups (list[GroupDetail] | Unset): Threat actor groups known to use the linked techniques
            inferred_chain_candidates (list[InferredChainCandidate] | None | Unset): AI-proposed technique candidates.
                Returned only when `include` contains `inferred_chain` and `techniques[]` is empty. Each entry is a low-
                confidence, non-authoritative analyst hint intended for human review.
            kev (KEVEntry | None | Unset): Known Exploited Vulnerabilities catalog status
            knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
            likely_tactics (list[str] | None | Unset): Likely ATT&CK tactic classes, such as `initial-access` or `lateral-
                movement`, inferred from the affected product vendor. Populated only when `techniques[]` is empty and a vendor
                profile is available. These are analyst hints, not technique IDs or authoritative attribution.
            misp (list[MISPAttribute] | Unset): Matching indicators from your organization's threat intelligence feed (self-
                hosted)
            mitigations (list[MitigationDetail] | Unset): Defensive mitigations for the linked techniques
            navigator (EnrichCVEResponseNavigatorType0 | None | Unset): ATT&CK Navigator layer JSON, consumable by the MITRE
                Navigator tool (https://mitre-attack.github.io/attack-navigator/) as-is — drop the value into the 'Open Existing
                Layer → Upload from Local' import. Returned only when `include=['navigator']` is requested. `null` when the
                layer could not be built. Useful for visualizing the CVE's technique footprint.
            nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
                this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
                include set.
            osv_advisories (list[OSVAdvisory] | Unset): OSV.dev advisories cross-referenced to this CVE id (GHSA / PYSEC /
                RUSTSEC / … records that alias the CVE — the open-source-ecosystem view of the same vulnerability, with per-
                ecosystem fixed versions). Returned when include=['osv']. Same OSV source as the dedicated enrich/package
                endpoint.
            poc (list[PoCEntry] | Unset): Proof-of-concept exploits from GitHub (sorted by stars)
            poc_source (list[PoCSourceEntry] | Unset): AI-assisted analysis of selected PoC repositories: trigger, affected
                path, preconditions, and mitigation. At most three entries are returned; raw source code is never returned.
            predictions (list[ThreatPrediction] | Unset): Threat predictions - probability each technique will be employed
            sector_context (None | SectorContext | Unset): Auto-detected industry sector context inferred from threat groups
                historically known to use the linked techniques. Returned only when `include=['sector_context']` is requested.
                `null` when no targeting groups are available.
            similar_cves (list[CVEMiniDetail] | Unset): Up to 15 CVEs with overlapping weakness/technique fingerprint,
                ranked by a weighted Jaccard similarity that may include CPE vendor:product overlap and CVSS vector Hamming
                similarity when available. Returned only when `include=['similar_cves']` is requested. Each entry carries a per-
                signal `signal_breakdown` for transparency.
            software (list[SoftwareDetail] | Unset): Malware and tools that employ the linked techniques
            ssvc (None | SSVCDecision | Unset): SSVC vulnerability-prioritization decision for this CVE. Populated when
                'ssvc' is in the request include set. Method (CERT/CC Deployer or CISA Coordinator) and stakeholder context
                (exposure, human_impact, etc.) come from the optional `stakeholder` request field; defaults apply when omitted.
                Inputs (`exploitation`, `automatable`, `technical_impact`) are derived from structured CVE evidence: KEV, EPSS,
                PoC count, and the CVSS vector.
            summary (None | str | Unset): AI-generated 3-5 sentence executive summary of the vulnerability context, woven
                from the structured signals in this response (CVSS, EPSS, KEV deadline, weaponization, top techniques, PoC
                presence). Returned only when `include=['summary']` is requested. `null` when AI summarization is unavailable or
                the layer was not requested. Check `errors[]` for a generation failure.
            techniques (list[TechniqueDetail] | Unset): ATT&CK techniques linked to this CVE through published
                vulnerability, CWE, and CAPEC relationships. CVEs sharing a broad CWE can have overlapping techniques; check
                `techniques_provenance` when CVE-specific precision matters.
            techniques_provenance (EnrichCVEResponseTechniquesProvenanceType0 | None | Unset): Precision class of
                `techniques[]`: `cve_specific` indicates vulnerability-specific evidence, `cwe_class` indicates broad weakness-
                class evidence, and `heuristic` indicates indirect evidence. `null` when `techniques` was not requested or none
                resolved. Lower-precision classes may reduce `confidence`.
            timeline (list[TimelineEntry] | Unset): EPSS score history for trend visualization. One entry per available
                scoring date. Returned only when `include=['timeline']` is requested. Pair with `epss_velocity` for derivative
                analysis.
            weaknesses (list[CWEDetail] | Unset): Root cause weakness classifications (CWE)
            weaponization_score (float | None | Unset): Composite 0-100 risk score that combines EPSS (exploit probability),
                KEV listing (active exploitation), public PoC presence/recency, and CVSS severity. Higher = more weaponized.
                `null` when none of the input signals are available. Use as a prioritization input alongside CVSS and EPSS;
                values >=70 warrant mention in summaries, >=85 lead the narrative.
            web (list[WebResult] | Unset): Web search results for exploits, PoCs, and advisories
    """

    affected_products: list[AffectedProduct] | Unset = UNSET
    attack_patterns: list[CAPECDetail] | Unset = UNSET
    campaigns: list[CampaignDetail] | Unset = UNSET
    confidence: Confidence | None | Unset = UNSET
    cve: CVEDetail | None | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    epss: EPSSScore | None | Unset = UNSET
    epss_velocity: EPSSVelocity | None | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    exploits: list[ExploitDetail] | Unset = UNSET
    groups: list[GroupDetail] | Unset = UNSET
    inferred_chain_candidates: list[InferredChainCandidate] | None | Unset = UNSET
    kev: KEVEntry | None | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    likely_tactics: list[str] | None | Unset = UNSET
    misp: list[MISPAttribute] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    navigator: EnrichCVEResponseNavigatorType0 | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    osv_advisories: list[OSVAdvisory] | Unset = UNSET
    poc: list[PoCEntry] | Unset = UNSET
    poc_source: list[PoCSourceEntry] | Unset = UNSET
    predictions: list[ThreatPrediction] | Unset = UNSET
    sector_context: None | SectorContext | Unset = UNSET
    similar_cves: list[CVEMiniDetail] | Unset = UNSET
    software: list[SoftwareDetail] | Unset = UNSET
    ssvc: None | SSVCDecision | Unset = UNSET
    summary: None | str | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    techniques_provenance: EnrichCVEResponseTechniquesProvenanceType0 | None | Unset = UNSET
    timeline: list[TimelineEntry] | Unset = UNSET
    weaknesses: list[CWEDetail] | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    web: list[WebResult] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.affected_product import AffectedProduct
        from ..models.campaign_detail import CampaignDetail
        from ..models.capec_detail import CAPECDetail
        from ..models.confidence import Confidence
        from ..models.cve_detail import CVEDetail
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.cwe_detail import CWEDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.enrich_cve_response_navigator_type_0 import EnrichCVEResponseNavigatorType0
        from ..models.epss_score import EPSSScore
        from ..models.epss_velocity import EPSSVelocity
        from ..models.error_detail import ErrorDetail
        from ..models.exploit_detail import ExploitDetail
        from ..models.group_detail import GroupDetail
        from ..models.inferred_chain_candidate import InferredChainCandidate
        from ..models.kev_entry import KEVEntry
        from ..models.knowledgebase_result import KnowledgebaseResult
        from ..models.misp_attribute import MISPAttribute
        from ..models.mitigation_detail import MitigationDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.osv_advisory import OSVAdvisory
        from ..models.po_c_entry import PoCEntry
        from ..models.po_c_source_entry import PoCSourceEntry
        from ..models.sector_context import SectorContext
        from ..models.software_detail import SoftwareDetail
        from ..models.ssvc_decision import SSVCDecision
        from ..models.technique_detail import TechniqueDetail
        from ..models.threat_prediction import ThreatPrediction
        from ..models.timeline_entry import TimelineEntry
        from ..models.web_result import WebResult

        affected_products: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_products, Unset):
            affected_products = []
            for affected_products_item_data in self.affected_products:
                affected_products_item = affected_products_item_data.to_dict()
                affected_products.append(affected_products_item)

        attack_patterns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attack_patterns, Unset):
            attack_patterns = []
            for attack_patterns_item_data in self.attack_patterns:
                attack_patterns_item = attack_patterns_item_data.to_dict()
                attack_patterns.append(attack_patterns_item)

        campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.campaigns, Unset):
            campaigns = []
            for campaigns_item_data in self.campaigns:
                campaigns_item = campaigns_item_data.to_dict()
                campaigns.append(campaigns_item)

        confidence: dict[str, Any] | None | Unset
        if isinstance(self.confidence, Unset):
            confidence = UNSET
        elif isinstance(self.confidence, Confidence):
            confidence = self.confidence.to_dict()
        else:
            confidence = self.confidence

        cve: dict[str, Any] | None | Unset
        if isinstance(self.cve, Unset):
            cve = UNSET
        elif isinstance(self.cve, CVEDetail):
            cve = self.cve.to_dict()
        else:
            cve = self.cve

        defend: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.defend, Unset):
            defend = []
            for defend_item_data in self.defend:
                defend_item = defend_item_data.to_dict()
                defend.append(defend_item)

        detections: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.detections, Unset):
            detections = []
            for detections_item_data in self.detections:
                detections_item = detections_item_data.to_dict()
                detections.append(detections_item)

        epss: dict[str, Any] | None | Unset
        if isinstance(self.epss, Unset):
            epss = UNSET
        elif isinstance(self.epss, EPSSScore):
            epss = self.epss.to_dict()
        else:
            epss = self.epss

        epss_velocity: dict[str, Any] | None | Unset
        if isinstance(self.epss_velocity, Unset):
            epss_velocity = UNSET
        elif isinstance(self.epss_velocity, EPSSVelocity):
            epss_velocity = self.epss_velocity.to_dict()
        else:
            epss_velocity = self.epss_velocity

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        exploits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.exploits, Unset):
            exploits = []
            for exploits_item_data in self.exploits:
                exploits_item = exploits_item_data.to_dict()
                exploits.append(exploits_item)

        groups: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = []
            for groups_item_data in self.groups:
                groups_item = groups_item_data.to_dict()
                groups.append(groups_item)

        inferred_chain_candidates: list[dict[str, Any]] | None | Unset
        if isinstance(self.inferred_chain_candidates, Unset):
            inferred_chain_candidates = UNSET
        elif isinstance(self.inferred_chain_candidates, list):
            inferred_chain_candidates = []
            for inferred_chain_candidates_type_0_item_data in self.inferred_chain_candidates:
                inferred_chain_candidates_type_0_item = inferred_chain_candidates_type_0_item_data.to_dict()
                inferred_chain_candidates.append(inferred_chain_candidates_type_0_item)

        else:
            inferred_chain_candidates = self.inferred_chain_candidates

        kev: dict[str, Any] | None | Unset
        if isinstance(self.kev, Unset):
            kev = UNSET
        elif isinstance(self.kev, KEVEntry):
            kev = self.kev.to_dict()
        else:
            kev = self.kev

        knowledgebase: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.knowledgebase, Unset):
            knowledgebase = []
            for knowledgebase_item_data in self.knowledgebase:
                knowledgebase_item = knowledgebase_item_data.to_dict()
                knowledgebase.append(knowledgebase_item)

        likely_tactics: list[str] | None | Unset
        if isinstance(self.likely_tactics, Unset):
            likely_tactics = UNSET
        elif isinstance(self.likely_tactics, list):
            likely_tactics = self.likely_tactics

        else:
            likely_tactics = self.likely_tactics

        misp: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.misp, Unset):
            misp = []
            for misp_item_data in self.misp:
                misp_item = misp_item_data.to_dict()
                misp.append(misp_item)

        mitigations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = []
            for mitigations_item_data in self.mitigations:
                mitigations_item = mitigations_item_data.to_dict()
                mitigations.append(mitigations_item)

        navigator: dict[str, Any] | None | Unset
        if isinstance(self.navigator, Unset):
            navigator = UNSET
        elif isinstance(self.navigator, EnrichCVEResponseNavigatorType0):
            navigator = self.navigator.to_dict()
        else:
            navigator = self.navigator

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        osv_advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.osv_advisories, Unset):
            osv_advisories = []
            for osv_advisories_item_data in self.osv_advisories:
                osv_advisories_item = osv_advisories_item_data.to_dict()
                osv_advisories.append(osv_advisories_item)

        poc: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.poc, Unset):
            poc = []
            for poc_item_data in self.poc:
                poc_item = poc_item_data.to_dict()
                poc.append(poc_item)

        poc_source: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.poc_source, Unset):
            poc_source = []
            for poc_source_item_data in self.poc_source:
                poc_source_item = poc_source_item_data.to_dict()
                poc_source.append(poc_source_item)

        predictions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.predictions, Unset):
            predictions = []
            for predictions_item_data in self.predictions:
                predictions_item = predictions_item_data.to_dict()
                predictions.append(predictions_item)

        sector_context: dict[str, Any] | None | Unset
        if isinstance(self.sector_context, Unset):
            sector_context = UNSET
        elif isinstance(self.sector_context, SectorContext):
            sector_context = self.sector_context.to_dict()
        else:
            sector_context = self.sector_context

        similar_cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.similar_cves, Unset):
            similar_cves = []
            for similar_cves_item_data in self.similar_cves:
                similar_cves_item = similar_cves_item_data.to_dict()
                similar_cves.append(similar_cves_item)

        software: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.software, Unset):
            software = []
            for software_item_data in self.software:
                software_item = software_item_data.to_dict()
                software.append(software_item)

        ssvc: dict[str, Any] | None | Unset
        if isinstance(self.ssvc, Unset):
            ssvc = UNSET
        elif isinstance(self.ssvc, SSVCDecision):
            ssvc = self.ssvc.to_dict()
        else:
            ssvc = self.ssvc

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = []
            for techniques_item_data in self.techniques:
                techniques_item = techniques_item_data.to_dict()
                techniques.append(techniques_item)

        techniques_provenance: None | str | Unset
        if isinstance(self.techniques_provenance, Unset):
            techniques_provenance = UNSET
        elif isinstance(self.techniques_provenance, EnrichCVEResponseTechniquesProvenanceType0):
            techniques_provenance = self.techniques_provenance.value
        else:
            techniques_provenance = self.techniques_provenance

        timeline: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.timeline, Unset):
            timeline = []
            for timeline_item_data in self.timeline:
                timeline_item = timeline_item_data.to_dict()
                timeline.append(timeline_item)

        weaknesses: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.weaknesses, Unset):
            weaknesses = []
            for weaknesses_item_data in self.weaknesses:
                weaknesses_item = weaknesses_item_data.to_dict()
                weaknesses.append(weaknesses_item)

        weaponization_score: float | None | Unset
        if isinstance(self.weaponization_score, Unset):
            weaponization_score = UNSET
        else:
            weaponization_score = self.weaponization_score

        web: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.web, Unset):
            web = []
            for web_item_data in self.web:
                web_item = web_item_data.to_dict()
                web.append(web_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if affected_products is not UNSET:
            field_dict["affected_products"] = affected_products
        if attack_patterns is not UNSET:
            field_dict["attack_patterns"] = attack_patterns
        if campaigns is not UNSET:
            field_dict["campaigns"] = campaigns
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if cve is not UNSET:
            field_dict["cve"] = cve
        if defend is not UNSET:
            field_dict["defend"] = defend
        if detections is not UNSET:
            field_dict["detections"] = detections
        if epss is not UNSET:
            field_dict["epss"] = epss
        if epss_velocity is not UNSET:
            field_dict["epss_velocity"] = epss_velocity
        if errors is not UNSET:
            field_dict["errors"] = errors
        if exploits is not UNSET:
            field_dict["exploits"] = exploits
        if groups is not UNSET:
            field_dict["groups"] = groups
        if inferred_chain_candidates is not UNSET:
            field_dict["inferred_chain_candidates"] = inferred_chain_candidates
        if kev is not UNSET:
            field_dict["kev"] = kev
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if likely_tactics is not UNSET:
            field_dict["likely_tactics"] = likely_tactics
        if misp is not UNSET:
            field_dict["misp"] = misp
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if osv_advisories is not UNSET:
            field_dict["osv_advisories"] = osv_advisories
        if poc is not UNSET:
            field_dict["poc"] = poc
        if poc_source is not UNSET:
            field_dict["poc_source"] = poc_source
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if sector_context is not UNSET:
            field_dict["sector_context"] = sector_context
        if similar_cves is not UNSET:
            field_dict["similar_cves"] = similar_cves
        if software is not UNSET:
            field_dict["software"] = software
        if ssvc is not UNSET:
            field_dict["ssvc"] = ssvc
        if summary is not UNSET:
            field_dict["summary"] = summary
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if techniques_provenance is not UNSET:
            field_dict["techniques_provenance"] = techniques_provenance
        if timeline is not UNSET:
            field_dict["timeline"] = timeline
        if weaknesses is not UNSET:
            field_dict["weaknesses"] = weaknesses
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score
        if web is not UNSET:
            field_dict["web"] = web

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.affected_product import AffectedProduct
        from ..models.campaign_detail import CampaignDetail
        from ..models.capec_detail import CAPECDetail
        from ..models.confidence import Confidence
        from ..models.cve_detail import CVEDetail
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.cwe_detail import CWEDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.enrich_cve_response_navigator_type_0 import EnrichCVEResponseNavigatorType0
        from ..models.epss_score import EPSSScore
        from ..models.epss_velocity import EPSSVelocity
        from ..models.error_detail import ErrorDetail
        from ..models.exploit_detail import ExploitDetail
        from ..models.group_detail import GroupDetail
        from ..models.inferred_chain_candidate import InferredChainCandidate
        from ..models.kev_entry import KEVEntry
        from ..models.knowledgebase_result import KnowledgebaseResult
        from ..models.misp_attribute import MISPAttribute
        from ..models.mitigation_detail import MitigationDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.osv_advisory import OSVAdvisory
        from ..models.po_c_entry import PoCEntry
        from ..models.po_c_source_entry import PoCSourceEntry
        from ..models.sector_context import SectorContext
        from ..models.software_detail import SoftwareDetail
        from ..models.ssvc_decision import SSVCDecision
        from ..models.technique_detail import TechniqueDetail
        from ..models.threat_prediction import ThreatPrediction
        from ..models.timeline_entry import TimelineEntry
        from ..models.web_result import WebResult

        d = dict(src_dict)
        _affected_products = d.pop("affected_products", UNSET)
        affected_products: list[AffectedProduct] | Unset = UNSET
        if _affected_products is not UNSET:
            affected_products = []
            for affected_products_item_data in _affected_products:
                affected_products_item = AffectedProduct.from_dict(affected_products_item_data)

                affected_products.append(affected_products_item)

        _attack_patterns = d.pop("attack_patterns", UNSET)
        attack_patterns: list[CAPECDetail] | Unset = UNSET
        if _attack_patterns is not UNSET:
            attack_patterns = []
            for attack_patterns_item_data in _attack_patterns:
                attack_patterns_item = CAPECDetail.from_dict(attack_patterns_item_data)

                attack_patterns.append(attack_patterns_item)

        _campaigns = d.pop("campaigns", UNSET)
        campaigns: list[CampaignDetail] | Unset = UNSET
        if _campaigns is not UNSET:
            campaigns = []
            for campaigns_item_data in _campaigns:
                campaigns_item = CampaignDetail.from_dict(campaigns_item_data)

                campaigns.append(campaigns_item)

        def _parse_confidence(data: object) -> Confidence | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                confidence_type_0 = Confidence.from_dict(data)

                return confidence_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(Confidence | None | Unset, data)

        confidence = _parse_confidence(d.pop("confidence", UNSET))

        def _parse_cve(data: object) -> CVEDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                cve_type_0 = CVEDetail.from_dict(data)

                return cve_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CVEDetail | None | Unset, data)

        cve = _parse_cve(d.pop("cve", UNSET))

        _defend = d.pop("defend", UNSET)
        defend: list[D3FENDDetail] | Unset = UNSET
        if _defend is not UNSET:
            defend = []
            for defend_item_data in _defend:
                defend_item = D3FENDDetail.from_dict(defend_item_data)

                defend.append(defend_item)

        _detections = d.pop("detections", UNSET)
        detections: list[DetectionDetail] | Unset = UNSET
        if _detections is not UNSET:
            detections = []
            for detections_item_data in _detections:
                detections_item = DetectionDetail.from_dict(detections_item_data)

                detections.append(detections_item)

        def _parse_epss(data: object) -> EPSSScore | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                epss_type_0 = EPSSScore.from_dict(data)

                return epss_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EPSSScore | None | Unset, data)

        epss = _parse_epss(d.pop("epss", UNSET))

        def _parse_epss_velocity(data: object) -> EPSSVelocity | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                epss_velocity_type_0 = EPSSVelocity.from_dict(data)

                return epss_velocity_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EPSSVelocity | None | Unset, data)

        epss_velocity = _parse_epss_velocity(d.pop("epss_velocity", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _exploits = d.pop("exploits", UNSET)
        exploits: list[ExploitDetail] | Unset = UNSET
        if _exploits is not UNSET:
            exploits = []
            for exploits_item_data in _exploits:
                exploits_item = ExploitDetail.from_dict(exploits_item_data)

                exploits.append(exploits_item)

        _groups = d.pop("groups", UNSET)
        groups: list[GroupDetail] | Unset = UNSET
        if _groups is not UNSET:
            groups = []
            for groups_item_data in _groups:
                groups_item = GroupDetail.from_dict(groups_item_data)

                groups.append(groups_item)

        def _parse_inferred_chain_candidates(data: object) -> list[InferredChainCandidate] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                inferred_chain_candidates_type_0 = []
                _inferred_chain_candidates_type_0 = data
                for inferred_chain_candidates_type_0_item_data in _inferred_chain_candidates_type_0:
                    inferred_chain_candidates_type_0_item = InferredChainCandidate.from_dict(
                        inferred_chain_candidates_type_0_item_data
                    )

                    inferred_chain_candidates_type_0.append(inferred_chain_candidates_type_0_item)

                return inferred_chain_candidates_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[InferredChainCandidate] | None | Unset, data)

        inferred_chain_candidates = _parse_inferred_chain_candidates(d.pop("inferred_chain_candidates", UNSET))

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

        _knowledgebase = d.pop("knowledgebase", UNSET)
        knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
        if _knowledgebase is not UNSET:
            knowledgebase = []
            for knowledgebase_item_data in _knowledgebase:
                knowledgebase_item = KnowledgebaseResult.from_dict(knowledgebase_item_data)

                knowledgebase.append(knowledgebase_item)

        def _parse_likely_tactics(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                likely_tactics_type_0 = cast(list[str], data)

                return likely_tactics_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        likely_tactics = _parse_likely_tactics(d.pop("likely_tactics", UNSET))

        _misp = d.pop("misp", UNSET)
        misp: list[MISPAttribute] | Unset = UNSET
        if _misp is not UNSET:
            misp = []
            for misp_item_data in _misp:
                misp_item = MISPAttribute.from_dict(misp_item_data)

                misp.append(misp_item)

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[MitigationDetail] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = MitigationDetail.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        def _parse_navigator(data: object) -> EnrichCVEResponseNavigatorType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                navigator_type_0 = EnrichCVEResponseNavigatorType0.from_dict(data)

                return navigator_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnrichCVEResponseNavigatorType0 | None | Unset, data)

        navigator = _parse_navigator(d.pop("navigator", UNSET))

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        _osv_advisories = d.pop("osv_advisories", UNSET)
        osv_advisories: list[OSVAdvisory] | Unset = UNSET
        if _osv_advisories is not UNSET:
            osv_advisories = []
            for osv_advisories_item_data in _osv_advisories:
                osv_advisories_item = OSVAdvisory.from_dict(osv_advisories_item_data)

                osv_advisories.append(osv_advisories_item)

        _poc = d.pop("poc", UNSET)
        poc: list[PoCEntry] | Unset = UNSET
        if _poc is not UNSET:
            poc = []
            for poc_item_data in _poc:
                poc_item = PoCEntry.from_dict(poc_item_data)

                poc.append(poc_item)

        _poc_source = d.pop("poc_source", UNSET)
        poc_source: list[PoCSourceEntry] | Unset = UNSET
        if _poc_source is not UNSET:
            poc_source = []
            for poc_source_item_data in _poc_source:
                poc_source_item = PoCSourceEntry.from_dict(poc_source_item_data)

                poc_source.append(poc_source_item)

        _predictions = d.pop("predictions", UNSET)
        predictions: list[ThreatPrediction] | Unset = UNSET
        if _predictions is not UNSET:
            predictions = []
            for predictions_item_data in _predictions:
                predictions_item = ThreatPrediction.from_dict(predictions_item_data)

                predictions.append(predictions_item)

        def _parse_sector_context(data: object) -> None | SectorContext | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                sector_context_type_0 = SectorContext.from_dict(data)

                return sector_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SectorContext | Unset, data)

        sector_context = _parse_sector_context(d.pop("sector_context", UNSET))

        _similar_cves = d.pop("similar_cves", UNSET)
        similar_cves: list[CVEMiniDetail] | Unset = UNSET
        if _similar_cves is not UNSET:
            similar_cves = []
            for similar_cves_item_data in _similar_cves:
                similar_cves_item = CVEMiniDetail.from_dict(similar_cves_item_data)

                similar_cves.append(similar_cves_item)

        _software = d.pop("software", UNSET)
        software: list[SoftwareDetail] | Unset = UNSET
        if _software is not UNSET:
            software = []
            for software_item_data in _software:
                software_item = SoftwareDetail.from_dict(software_item_data)

                software.append(software_item)

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

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        _techniques = d.pop("techniques", UNSET)
        techniques: list[TechniqueDetail] | Unset = UNSET
        if _techniques is not UNSET:
            techniques = []
            for techniques_item_data in _techniques:
                techniques_item = TechniqueDetail.from_dict(techniques_item_data)

                techniques.append(techniques_item)

        def _parse_techniques_provenance(data: object) -> EnrichCVEResponseTechniquesProvenanceType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                techniques_provenance_type_0 = EnrichCVEResponseTechniquesProvenanceType0(data)

                return techniques_provenance_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnrichCVEResponseTechniquesProvenanceType0 | None | Unset, data)

        techniques_provenance = _parse_techniques_provenance(d.pop("techniques_provenance", UNSET))

        _timeline = d.pop("timeline", UNSET)
        timeline: list[TimelineEntry] | Unset = UNSET
        if _timeline is not UNSET:
            timeline = []
            for timeline_item_data in _timeline:
                timeline_item = TimelineEntry.from_dict(timeline_item_data)

                timeline.append(timeline_item)

        _weaknesses = d.pop("weaknesses", UNSET)
        weaknesses: list[CWEDetail] | Unset = UNSET
        if _weaknesses is not UNSET:
            weaknesses = []
            for weaknesses_item_data in _weaknesses:
                weaknesses_item = CWEDetail.from_dict(weaknesses_item_data)

                weaknesses.append(weaknesses_item)

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        _web = d.pop("web", UNSET)
        web: list[WebResult] | Unset = UNSET
        if _web is not UNSET:
            web = []
            for web_item_data in _web:
                web_item = WebResult.from_dict(web_item_data)

                web.append(web_item)

        enrich_cve_response = cls(
            affected_products=affected_products,
            attack_patterns=attack_patterns,
            campaigns=campaigns,
            confidence=confidence,
            cve=cve,
            defend=defend,
            detections=detections,
            epss=epss,
            epss_velocity=epss_velocity,
            errors=errors,
            exploits=exploits,
            groups=groups,
            inferred_chain_candidates=inferred_chain_candidates,
            kev=kev,
            knowledgebase=knowledgebase,
            likely_tactics=likely_tactics,
            misp=misp,
            mitigations=mitigations,
            navigator=navigator,
            nist_controls=nist_controls,
            osv_advisories=osv_advisories,
            poc=poc,
            poc_source=poc_source,
            predictions=predictions,
            sector_context=sector_context,
            similar_cves=similar_cves,
            software=software,
            ssvc=ssvc,
            summary=summary,
            techniques=techniques,
            techniques_provenance=techniques_provenance,
            timeline=timeline,
            weaknesses=weaknesses,
            weaponization_score=weaponization_score,
            web=web,
        )

        enrich_cve_response.additional_properties = d
        return enrich_cve_response

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
