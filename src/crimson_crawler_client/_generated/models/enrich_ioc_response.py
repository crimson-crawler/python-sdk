from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.campaign_detail import CampaignDetail
    from ..models.cisa_campaign_advisory import CISACampaignAdvisory
    from ..models.cve_mini_detail import CVEMiniDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.domain_context import DomainContext
    from ..models.enrich_ioc_response_navigator_type_0 import EnrichIOCResponseNavigatorType0
    from ..models.error_detail import ErrorDetail
    from ..models.galaxy_cluster_detail import GalaxyClusterDetail
    from ..models.group_detail import GroupDetail
    from ..models.hashlookup_record import HashlookupRecord
    from ..models.inferred_chain_candidate import InferredChainCandidate
    from ..models.knowledgebase_result import KnowledgebaseResult
    from ..models.listed_on_entry import ListedOnEntry
    from ..models.misp_attribute import MISPAttribute
    from ..models.misp_feed_hit import MISPFeedHit
    from ..models.mitigation_detail import MitigationDetail
    from ..models.network_context import NetworkContext
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.po_c_entry import PoCEntry
    from ..models.software_detail import SoftwareDetail
    from ..models.technique_detail import TechniqueDetail
    from ..models.threat_assessment import ThreatAssessment
    from ..models.threat_prediction import ThreatPrediction
    from ..models.warninglist_result import WarninglistResult


T = TypeVar("T", bound="EnrichIOCResponse")


@_attrs_define
class EnrichIOCResponse:
    """Response from `/v1/enrich/ioc`.

    Returns threat events, adversary techniques, predictions, and an optional AI summary. Use `include`
    to control depth. When published relationships yield no techniques, request `inferred_chain` to
    receive low-confidence analyst hints in `inferred_chain_candidates`.

        Attributes:
            type_ (str): Indicator type
            value (str): The indicator value that was enriched
            campaigns (list[CampaignDetail] | Unset): Threat campaigns that used the linked techniques
            cisa_campaigns (list[CISACampaignAdvisory] | Unset): CISA joint cybersecurity advisories (AA-series) whose STIX
                bundle publishes this indicator, with the matching observables in each advisory's `matched_indicators`. Opt-in
                via include=['cisa_campaigns']; matched on the normalised observable type (an `ip-src`/`ip-dst`/`ip` value
                matches IPv4/IPv6 rows, `hostname` matches `domain-name`, hash and domain matching is case-insensitive).
            cves (list[CVEMiniDetail] | Unset): CVEs referenced in linked threat events
            defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
                techniques. The default form omits each row's `description`, `aliases`, STIX `pattern` and `stix_id`; request
                include=['defend_full'] for them. The STIX licence marking (`object_marking_refs`) is kept in both forms.
            detections (list[DetectionDetail] | Unset): Detection data sources and components for the linked techniques
            domain_context (DomainContext | None | Unset): Domain registration facts from the TLD registry's RDAP service,
                found through IANA's bootstrap. Opt-in via include=['domain_context']; applies to `domain`, `hostname` and the
                host of a `url`. null when the domain is unregistered, its TLD publishes no https RDAP service, or the read
                failed (the failure is reported in `errors[]`).
            errors (list[ErrorDetail] | Unset): Partial failure details
            galaxy_clusters (list[GalaxyClusterDetail] | Unset): Fully-resolved MISP Galaxy clusters referenced by this
                indicator's attributes (actor, malware, tool, technique profiles with synonyms, source, relations). Populated by
                include=['galaxies'] or include=['galaxy_clusters_full']; the default form empties each row's
                `inbound_relations`, which `galaxy_clusters_full` restores.
            galaxy_clusters_total (int | Unset): Distinct MISP galaxy clusters referenced before the row cap (0 when not
                requested) Default: 0.
            galaxy_clusters_truncated (bool | Unset): True only when the row cap cut clusters: `galaxy_clusters_total` names
                how many were referenced. The compact form empties each row's `inbound_relations` without setting this flag;
                request include=['galaxy_clusters_full'] for the populated rows. Default: False.
            groups (list[GroupDetail] | Unset): Threat actor groups known to use the linked techniques
            hashlookup (HashlookupRecord | None | Unset): CIRCL hashlookup / NSRL known-good verdict for a hash indicator
                (md5/sha1/sha256). Opt-in via include=['hashlookup']; null for a non-hash indicator. A 404 answer is
                `known=false` with status `ok`; a read failure is status `unavailable` plus an `errors[]` entry (step
                `fetch_hashlookup`).
            identifier_resolved (bool | None | Unset): Whether the indicator matched any threat intelligence. `false` means
                the configured feeds returned no matching attributes, galaxies, or sightings — it does NOT mean the indicator is
                benign, only that this deployment carries nothing for it. `true` means some matching intelligence. `null` when
                no lookup was attempted — an `include` set that reads neither `misp_attributes`/`galaxies`/`sightings` nor a
                technique-derived layer, which reads the same attributes for their galaxy tags.
            inferred_chain_candidates (list[InferredChainCandidate] | None | Unset): AI-proposed technique candidates.
                Returned only when `include` contains `inferred_chain` and `techniques[]` is empty. Each entry is a low-
                confidence, non-authoritative analyst hint intended for human review.
            knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
            listed_on (list[ListedOnEntry] | Unset): Every list this value appears on, unified across our curated MISP feed
                caches and the seeded Spamhaus DROP / ASN-DROP corpora, each entry naming how it matched (`exact`, `cidr`,
                `asn`). Opt-in via include=['listed_on']; MISP feed-cache reads stay exact-value (unchanged) — the CIDR and ASN
                matches come from the Spamhaus prefix trie and are what an exact-value cache cannot express.
            matched_value_types (list[str] | Unset): MISP attribute types that actually matched this value, sorted. For `ip-
                src` and `ip-dst` (and the `ip` alias) BOTH directions are searched, so this can name the direction the caller
                did not ask for — an indicator stored the other way round used to look like no match at all. Requires
                `misp_attributes`, `galaxies` or `sightings`; empty when no attribute lookup was performed.
            misp_attributes (list[MISPAttribute] | Unset): Matching threat intelligence indicators
            misp_feed_hits (list[MISPFeedHit] | Unset): Feeds in our curated MISP that also carry this indicator (list:
                https://crimsoncrawler.com/docs/guides/data-sources/#our-curated-misp).
            mitigations (list[MitigationDetail] | Unset): Defensive mitigations for the linked techniques
            navigator (EnrichIOCResponseNavigatorType0 | None | Unset): ATT&CK Navigator layer JSON for visualization in
                MITRE's Navigator tool
            network_context (NetworkContext | None | Unset): ASN, AS name, registration country and covering prefix for an
                IP indicator, from the seeded iptoasn corpus (PDDL). Opt-in via include=['network_context']; null for a non-IP
                value and for an IP the corpus does not cover. `country` is the RIR's registration country, not geolocation.
            nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
                this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
                include set.
            poc (list[PoCEntry] | Unset): PoC repositories for linked CVEs, capped to the 15 highest-starred repositories in
                a stable order. The default form omits each row's `description`; request include=['poc_full'] for every row.
            poc_total (int | Unset): How many PoC repositories matched, before the summary cap (0 when not published)
                Default: 0.
            poc_truncated (bool | Unset): True when `poc` is the relevance-ordered cap; request include=['poc_full'] for
                every row Default: False.
            predictions (list[ThreatPrediction] | Unset): Threat predictions for linked techniques
            sightings_count (int | Unset): Total confirmed sightings across linked events Default: 0.
            software (list[SoftwareDetail] | Unset): Malware and tools that employ the linked techniques
            summary (None | str | Unset): AI-generated summary of the indicator threat context
            techniques (list[TechniqueDetail] | Unset): ATT&CK techniques linked through threat events
            threat_assessment (None | ThreatAssessment | Unset): Computed threat verdict with confidence score
            warninglist (None | Unset | WarninglistResult): False-positive check against known-benign indicator lists
    """

    type_: str
    value: str
    campaigns: list[CampaignDetail] | Unset = UNSET
    cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
    cves: list[CVEMiniDetail] | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    domain_context: DomainContext | None | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    galaxy_clusters: list[GalaxyClusterDetail] | Unset = UNSET
    galaxy_clusters_total: int | Unset = 0
    galaxy_clusters_truncated: bool | Unset = False
    groups: list[GroupDetail] | Unset = UNSET
    hashlookup: HashlookupRecord | None | Unset = UNSET
    identifier_resolved: bool | None | Unset = UNSET
    inferred_chain_candidates: list[InferredChainCandidate] | None | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    listed_on: list[ListedOnEntry] | Unset = UNSET
    matched_value_types: list[str] | Unset = UNSET
    misp_attributes: list[MISPAttribute] | Unset = UNSET
    misp_feed_hits: list[MISPFeedHit] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    navigator: EnrichIOCResponseNavigatorType0 | None | Unset = UNSET
    network_context: NetworkContext | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    poc: list[PoCEntry] | Unset = UNSET
    poc_total: int | Unset = 0
    poc_truncated: bool | Unset = False
    predictions: list[ThreatPrediction] | Unset = UNSET
    sightings_count: int | Unset = 0
    software: list[SoftwareDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    threat_assessment: None | ThreatAssessment | Unset = UNSET
    warninglist: None | Unset | WarninglistResult = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.cve_mini_detail import CVEMiniDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.detection_detail import DetectionDetail  # noqa: PLC0415
        from ..models.domain_context import DomainContext  # noqa: PLC0415
        from ..models.enrich_ioc_response_navigator_type_0 import EnrichIOCResponseNavigatorType0  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.galaxy_cluster_detail import GalaxyClusterDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.hashlookup_record import HashlookupRecord  # noqa: PLC0415
        from ..models.inferred_chain_candidate import InferredChainCandidate  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415
        from ..models.listed_on_entry import ListedOnEntry  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_feed_hit import MISPFeedHit  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.network_context import NetworkContext  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.po_c_entry import PoCEntry  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_assessment import ThreatAssessment  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415
        from ..models.warninglist_result import WarninglistResult  # noqa: PLC0415

        type_ = self.type_

        value = self.value

        campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.campaigns, Unset):
            campaigns = []
            for campaigns_item_data in self.campaigns:
                campaigns_item = campaigns_item_data.to_dict()
                campaigns.append(campaigns_item)

        cisa_campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cisa_campaigns, Unset):
            cisa_campaigns = []
            for cisa_campaigns_item_data in self.cisa_campaigns:
                cisa_campaigns_item = cisa_campaigns_item_data.to_dict()
                cisa_campaigns.append(cisa_campaigns_item)

        cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cves, Unset):
            cves = []
            for cves_item_data in self.cves:
                cves_item = cves_item_data.to_dict()
                cves.append(cves_item)

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

        domain_context: dict[str, Any] | None | Unset
        if isinstance(self.domain_context, Unset):
            domain_context = UNSET
        elif isinstance(self.domain_context, DomainContext):
            domain_context = self.domain_context.to_dict()
        else:
            domain_context = self.domain_context

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        galaxy_clusters: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.galaxy_clusters, Unset):
            galaxy_clusters = []
            for galaxy_clusters_item_data in self.galaxy_clusters:
                galaxy_clusters_item = galaxy_clusters_item_data.to_dict()
                galaxy_clusters.append(galaxy_clusters_item)

        galaxy_clusters_total = self.galaxy_clusters_total

        galaxy_clusters_truncated = self.galaxy_clusters_truncated

        groups: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = []
            for groups_item_data in self.groups:
                groups_item = groups_item_data.to_dict()
                groups.append(groups_item)

        hashlookup: dict[str, Any] | None | Unset
        if isinstance(self.hashlookup, Unset):
            hashlookup = UNSET
        elif isinstance(self.hashlookup, HashlookupRecord):
            hashlookup = self.hashlookup.to_dict()
        else:
            hashlookup = self.hashlookup

        identifier_resolved: bool | None | Unset
        if isinstance(self.identifier_resolved, Unset):
            identifier_resolved = UNSET
        else:
            identifier_resolved = self.identifier_resolved

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

        knowledgebase: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.knowledgebase, Unset):
            knowledgebase = []
            for knowledgebase_item_data in self.knowledgebase:
                knowledgebase_item = knowledgebase_item_data.to_dict()
                knowledgebase.append(knowledgebase_item)

        listed_on: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.listed_on, Unset):
            listed_on = []
            for listed_on_item_data in self.listed_on:
                listed_on_item = listed_on_item_data.to_dict()
                listed_on.append(listed_on_item)

        matched_value_types: list[str] | Unset = UNSET
        if not isinstance(self.matched_value_types, Unset):
            matched_value_types = self.matched_value_types

        misp_attributes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.misp_attributes, Unset):
            misp_attributes = []
            for misp_attributes_item_data in self.misp_attributes:
                misp_attributes_item = misp_attributes_item_data.to_dict()
                misp_attributes.append(misp_attributes_item)

        misp_feed_hits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.misp_feed_hits, Unset):
            misp_feed_hits = []
            for misp_feed_hits_item_data in self.misp_feed_hits:
                misp_feed_hits_item = misp_feed_hits_item_data.to_dict()
                misp_feed_hits.append(misp_feed_hits_item)

        mitigations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = []
            for mitigations_item_data in self.mitigations:
                mitigations_item = mitigations_item_data.to_dict()
                mitigations.append(mitigations_item)

        navigator: dict[str, Any] | None | Unset
        if isinstance(self.navigator, Unset):
            navigator = UNSET
        elif isinstance(self.navigator, EnrichIOCResponseNavigatorType0):
            navigator = self.navigator.to_dict()
        else:
            navigator = self.navigator

        network_context: dict[str, Any] | None | Unset
        if isinstance(self.network_context, Unset):
            network_context = UNSET
        elif isinstance(self.network_context, NetworkContext):
            network_context = self.network_context.to_dict()
        else:
            network_context = self.network_context

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        poc: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.poc, Unset):
            poc = []
            for poc_item_data in self.poc:
                poc_item = poc_item_data.to_dict()
                poc.append(poc_item)

        poc_total = self.poc_total

        poc_truncated = self.poc_truncated

        predictions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.predictions, Unset):
            predictions = []
            for predictions_item_data in self.predictions:
                predictions_item = predictions_item_data.to_dict()
                predictions.append(predictions_item)

        sightings_count = self.sightings_count

        software: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.software, Unset):
            software = []
            for software_item_data in self.software:
                software_item = software_item_data.to_dict()
                software.append(software_item)

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

        threat_assessment: dict[str, Any] | None | Unset
        if isinstance(self.threat_assessment, Unset):
            threat_assessment = UNSET
        elif isinstance(self.threat_assessment, ThreatAssessment):
            threat_assessment = self.threat_assessment.to_dict()
        else:
            threat_assessment = self.threat_assessment

        warninglist: dict[str, Any] | None | Unset
        if isinstance(self.warninglist, Unset):
            warninglist = UNSET
        elif isinstance(self.warninglist, WarninglistResult):
            warninglist = self.warninglist.to_dict()
        else:
            warninglist = self.warninglist

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "value": value,
            }
        )
        if campaigns is not UNSET:
            field_dict["campaigns"] = campaigns
        if cisa_campaigns is not UNSET:
            field_dict["cisa_campaigns"] = cisa_campaigns
        if cves is not UNSET:
            field_dict["cves"] = cves
        if defend is not UNSET:
            field_dict["defend"] = defend
        if detections is not UNSET:
            field_dict["detections"] = detections
        if domain_context is not UNSET:
            field_dict["domain_context"] = domain_context
        if errors is not UNSET:
            field_dict["errors"] = errors
        if galaxy_clusters is not UNSET:
            field_dict["galaxy_clusters"] = galaxy_clusters
        if galaxy_clusters_total is not UNSET:
            field_dict["galaxy_clusters_total"] = galaxy_clusters_total
        if galaxy_clusters_truncated is not UNSET:
            field_dict["galaxy_clusters_truncated"] = galaxy_clusters_truncated
        if groups is not UNSET:
            field_dict["groups"] = groups
        if hashlookup is not UNSET:
            field_dict["hashlookup"] = hashlookup
        if identifier_resolved is not UNSET:
            field_dict["identifier_resolved"] = identifier_resolved
        if inferred_chain_candidates is not UNSET:
            field_dict["inferred_chain_candidates"] = inferred_chain_candidates
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if listed_on is not UNSET:
            field_dict["listed_on"] = listed_on
        if matched_value_types is not UNSET:
            field_dict["matched_value_types"] = matched_value_types
        if misp_attributes is not UNSET:
            field_dict["misp_attributes"] = misp_attributes
        if misp_feed_hits is not UNSET:
            field_dict["misp_feed_hits"] = misp_feed_hits
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if network_context is not UNSET:
            field_dict["network_context"] = network_context
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if poc is not UNSET:
            field_dict["poc"] = poc
        if poc_total is not UNSET:
            field_dict["poc_total"] = poc_total
        if poc_truncated is not UNSET:
            field_dict["poc_truncated"] = poc_truncated
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if sightings_count is not UNSET:
            field_dict["sightings_count"] = sightings_count
        if software is not UNSET:
            field_dict["software"] = software
        if summary is not UNSET:
            field_dict["summary"] = summary
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if threat_assessment is not UNSET:
            field_dict["threat_assessment"] = threat_assessment
        if warninglist is not UNSET:
            field_dict["warninglist"] = warninglist

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.cisa_campaign_advisory import CISACampaignAdvisory  # noqa: PLC0415
        from ..models.cve_mini_detail import CVEMiniDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.detection_detail import DetectionDetail  # noqa: PLC0415
        from ..models.domain_context import DomainContext  # noqa: PLC0415
        from ..models.enrich_ioc_response_navigator_type_0 import EnrichIOCResponseNavigatorType0  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.galaxy_cluster_detail import GalaxyClusterDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.hashlookup_record import HashlookupRecord  # noqa: PLC0415
        from ..models.inferred_chain_candidate import InferredChainCandidate  # noqa: PLC0415
        from ..models.knowledgebase_result import KnowledgebaseResult  # noqa: PLC0415
        from ..models.listed_on_entry import ListedOnEntry  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_feed_hit import MISPFeedHit  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.network_context import NetworkContext  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.po_c_entry import PoCEntry  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_assessment import ThreatAssessment  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415
        from ..models.warninglist_result import WarninglistResult  # noqa: PLC0415

        d = dict(src_dict)
        type_ = d.pop("type")

        value = d.pop("value")

        _campaigns = d.pop("campaigns", UNSET)
        campaigns: list[CampaignDetail] | Unset = UNSET
        if _campaigns is not UNSET:
            campaigns = []
            for campaigns_item_data in _campaigns:
                campaigns_item = CampaignDetail.from_dict(campaigns_item_data)

                campaigns.append(campaigns_item)

        _cisa_campaigns = d.pop("cisa_campaigns", UNSET)
        cisa_campaigns: list[CISACampaignAdvisory] | Unset = UNSET
        if _cisa_campaigns is not UNSET:
            cisa_campaigns = []
            for cisa_campaigns_item_data in _cisa_campaigns:
                cisa_campaigns_item = CISACampaignAdvisory.from_dict(cisa_campaigns_item_data)

                cisa_campaigns.append(cisa_campaigns_item)

        _cves = d.pop("cves", UNSET)
        cves: list[CVEMiniDetail] | Unset = UNSET
        if _cves is not UNSET:
            cves = []
            for cves_item_data in _cves:
                cves_item = CVEMiniDetail.from_dict(cves_item_data)

                cves.append(cves_item)

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

        def _parse_domain_context(data: object) -> DomainContext | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                domain_context_type_0 = DomainContext.from_dict(data)

                return domain_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DomainContext | None | Unset, data)

        domain_context = _parse_domain_context(d.pop("domain_context", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _galaxy_clusters = d.pop("galaxy_clusters", UNSET)
        galaxy_clusters: list[GalaxyClusterDetail] | Unset = UNSET
        if _galaxy_clusters is not UNSET:
            galaxy_clusters = []
            for galaxy_clusters_item_data in _galaxy_clusters:
                galaxy_clusters_item = GalaxyClusterDetail.from_dict(galaxy_clusters_item_data)

                galaxy_clusters.append(galaxy_clusters_item)

        galaxy_clusters_total = d.pop("galaxy_clusters_total", UNSET)

        galaxy_clusters_truncated = d.pop("galaxy_clusters_truncated", UNSET)

        _groups = d.pop("groups", UNSET)
        groups: list[GroupDetail] | Unset = UNSET
        if _groups is not UNSET:
            groups = []
            for groups_item_data in _groups:
                groups_item = GroupDetail.from_dict(groups_item_data)

                groups.append(groups_item)

        def _parse_hashlookup(data: object) -> HashlookupRecord | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                hashlookup_type_0 = HashlookupRecord.from_dict(data)

                return hashlookup_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(HashlookupRecord | None | Unset, data)

        hashlookup = _parse_hashlookup(d.pop("hashlookup", UNSET))

        def _parse_identifier_resolved(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        identifier_resolved = _parse_identifier_resolved(d.pop("identifier_resolved", UNSET))

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

        _knowledgebase = d.pop("knowledgebase", UNSET)
        knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
        if _knowledgebase is not UNSET:
            knowledgebase = []
            for knowledgebase_item_data in _knowledgebase:
                knowledgebase_item = KnowledgebaseResult.from_dict(knowledgebase_item_data)

                knowledgebase.append(knowledgebase_item)

        _listed_on = d.pop("listed_on", UNSET)
        listed_on: list[ListedOnEntry] | Unset = UNSET
        if _listed_on is not UNSET:
            listed_on = []
            for listed_on_item_data in _listed_on:
                listed_on_item = ListedOnEntry.from_dict(listed_on_item_data)

                listed_on.append(listed_on_item)

        matched_value_types = cast(list[str], d.pop("matched_value_types", UNSET))

        _misp_attributes = d.pop("misp_attributes", UNSET)
        misp_attributes: list[MISPAttribute] | Unset = UNSET
        if _misp_attributes is not UNSET:
            misp_attributes = []
            for misp_attributes_item_data in _misp_attributes:
                misp_attributes_item = MISPAttribute.from_dict(misp_attributes_item_data)

                misp_attributes.append(misp_attributes_item)

        _misp_feed_hits = d.pop("misp_feed_hits", UNSET)
        misp_feed_hits: list[MISPFeedHit] | Unset = UNSET
        if _misp_feed_hits is not UNSET:
            misp_feed_hits = []
            for misp_feed_hits_item_data in _misp_feed_hits:
                misp_feed_hits_item = MISPFeedHit.from_dict(misp_feed_hits_item_data)

                misp_feed_hits.append(misp_feed_hits_item)

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[MitigationDetail] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = MitigationDetail.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        def _parse_navigator(data: object) -> EnrichIOCResponseNavigatorType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                navigator_type_0 = EnrichIOCResponseNavigatorType0.from_dict(data)

                return navigator_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnrichIOCResponseNavigatorType0 | None | Unset, data)

        navigator = _parse_navigator(d.pop("navigator", UNSET))

        def _parse_network_context(data: object) -> NetworkContext | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                network_context_type_0 = NetworkContext.from_dict(data)

                return network_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(NetworkContext | None | Unset, data)

        network_context = _parse_network_context(d.pop("network_context", UNSET))

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        _poc = d.pop("poc", UNSET)
        poc: list[PoCEntry] | Unset = UNSET
        if _poc is not UNSET:
            poc = []
            for poc_item_data in _poc:
                poc_item = PoCEntry.from_dict(poc_item_data)

                poc.append(poc_item)

        poc_total = d.pop("poc_total", UNSET)

        poc_truncated = d.pop("poc_truncated", UNSET)

        _predictions = d.pop("predictions", UNSET)
        predictions: list[ThreatPrediction] | Unset = UNSET
        if _predictions is not UNSET:
            predictions = []
            for predictions_item_data in _predictions:
                predictions_item = ThreatPrediction.from_dict(predictions_item_data)

                predictions.append(predictions_item)

        sightings_count = d.pop("sightings_count", UNSET)

        _software = d.pop("software", UNSET)
        software: list[SoftwareDetail] | Unset = UNSET
        if _software is not UNSET:
            software = []
            for software_item_data in _software:
                software_item = SoftwareDetail.from_dict(software_item_data)

                software.append(software_item)

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

        def _parse_threat_assessment(data: object) -> None | ThreatAssessment | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                threat_assessment_type_0 = ThreatAssessment.from_dict(data)

                return threat_assessment_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ThreatAssessment | Unset, data)

        threat_assessment = _parse_threat_assessment(d.pop("threat_assessment", UNSET))

        def _parse_warninglist(data: object) -> None | Unset | WarninglistResult:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                warninglist_type_0 = WarninglistResult.from_dict(data)

                return warninglist_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | WarninglistResult, data)

        warninglist = _parse_warninglist(d.pop("warninglist", UNSET))

        enrich_ioc_response = cls(
            type_=type_,
            value=value,
            campaigns=campaigns,
            cisa_campaigns=cisa_campaigns,
            cves=cves,
            defend=defend,
            detections=detections,
            domain_context=domain_context,
            errors=errors,
            galaxy_clusters=galaxy_clusters,
            galaxy_clusters_total=galaxy_clusters_total,
            galaxy_clusters_truncated=galaxy_clusters_truncated,
            groups=groups,
            hashlookup=hashlookup,
            identifier_resolved=identifier_resolved,
            inferred_chain_candidates=inferred_chain_candidates,
            knowledgebase=knowledgebase,
            listed_on=listed_on,
            matched_value_types=matched_value_types,
            misp_attributes=misp_attributes,
            misp_feed_hits=misp_feed_hits,
            mitigations=mitigations,
            navigator=navigator,
            network_context=network_context,
            nist_controls=nist_controls,
            poc=poc,
            poc_total=poc_total,
            poc_truncated=poc_truncated,
            predictions=predictions,
            sightings_count=sightings_count,
            software=software,
            summary=summary,
            techniques=techniques,
            threat_assessment=threat_assessment,
            warninglist=warninglist,
        )

        enrich_ioc_response.additional_properties = d
        return enrich_ioc_response

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
