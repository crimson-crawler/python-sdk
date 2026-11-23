from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.assess_ioc_portfolio_response_warninglist_hits_item import (
        AssessIOCPortfolioResponseWarninglistHitsItem,
    )
    from ..models.campaign_detail import CampaignDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.error_detail import ErrorDetail
    from ..models.galaxy_cluster_detail import GalaxyClusterDetail
    from ..models.group_detail import GroupDetail
    from ..models.misp_attribute import MISPAttribute
    from ..models.misp_event import MISPEvent
    from ..models.misp_feed_hit import MISPFeedHit
    from ..models.mitigation_detail import MitigationDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.software_detail import SoftwareDetail
    from ..models.technique_detail import TechniqueDetail
    from ..models.threat_prediction import ThreatPrediction


T = TypeVar("T", bound="AssessIOCPortfolioResponse")


@_attrs_define
class AssessIOCPortfolioResponse:
    """Unified threat picture across multiple indicators of compromise.

    Attributes:
        campaigns (list[CampaignDetail] | Unset): Campaigns linked across all IOCs
        defend (list[D3FENDDetail] | Unset): D3FEND countermeasures for the combined technique surface
        detections (list[DetectionDetail] | Unset): Deduplicated detections across all techniques
        errors (list[ErrorDetail] | Unset): Partial failure details
        galaxy_clusters (list[GalaxyClusterDetail] | Unset): Full MISP Galaxy cluster profiles (actor / malware / tool /
            technique — synonyms, source, relations) resolved from the cluster refs on the portfolio's MISP attributes.
            Returned when include=['galaxies'] — the multi-IOC sibling of enrich/ioc's galaxies include; deduped by UUID and
            capped.
        groups (list[GroupDetail] | Unset): Threat groups linked across all IOCs
        identifier_resolved (bool | None | Unset): Whether any assessed indicator matched locally held threat
            intelligence. `false` means none of them matched anything, so every derived layer below (`misp_attributes`,
            `misp_events`, `techniques`, `groups`, …) is empty for that reason rather than because the indicators exist and
            simply carry no linked intelligence — the two were previously indistinguishable. `null` when the request never
            asked for the correlation at all — an `include` set that does not read MISP's attribute index (no
            `misp_attributes`/`galaxies`/`sightings`, and no technique-derived layer, which reads the same attributes for
            its galaxy tags) — where an empty payload says nothing about the indicators.
        indicators_assessed (int | Unset): Number of IOCs processed Default: 0.
        misp_attributes (list[MISPAttribute] | Unset): Deduplicated threat indicators across all IOCs. **Summary rows by
            default** — `id`, `uuid`, `type`, `value`, `category`, `to_ids`, `event_id`, `event_info`, `event_date`,
            `threat_level`, `first_seen`, `last_seen`, `sighting_count`, `timestamp` — capped at 100; the per-row bodies
            (galaxies, tags, notices, comments) are what made a single populated indicator multi-megabyte. Add
            `misp_attributes_full` to the include set for the full rows (capped at 200), or page freely through
            `/v1/search/misp`. Check `misp_attributes_total` and `misp_attributes_truncated`.
        misp_attributes_read_truncated (bool | Unset): True when the MISP attribute read stopped at its page bound, so
            later matching attributes were never read — the technique layers derive from every attribute, so this is
            reported rather than silently dropped. See `errors[]` for the `read_truncated` entry. Default: False.
        misp_attributes_total (int | Unset): Total deduplicated attributes found before the published cap was applied
            Default: 0.
        misp_attributes_truncated (bool | Unset): True when fewer attributes were published than found — see
            `misp_attributes_total`, and request `misp_attributes_full` or page `/v1/search/misp` for the rest Default:
            False.
        misp_events (list[MISPEvent] | Unset): Deduplicated threat events across all IOCs. Up to 10 parent events are
            read; the response has a separate maximum of 25. **Summary rows by default** — `id`, `uuid`, `info`, `date`,
            `threat_level_id`, `analysis`, `published`, `first_publication`, `org`, `attribute_count`, `timestamp`,
            `tag_names`. The section is read with MISP's `metadata: true`, so an event body is never materialised unless you
            ask for it — that body is ~1.35 MB per populated event (prod, 2026-10-26) and was most of this endpoint's bytes.
            Add `misp_events_full` for the full event bodies. Check `misp_events_truncated` and `misp_events_total` to see
            whether more exist, and page the remainder from `/v1/search/misp`.
        misp_events_total (int | Unset): Total deduplicated correlated events found before the event read bound Default:
            0.
        misp_events_truncated (bool | Unset): True when more events were found than returned — see `misp_events_total`
            Default: False.
        misp_feed_hits (list[MISPFeedHit] | Unset): Feeds in our curated MISP that also carry the assessed indicators
            (list: https://crimsoncrawler.com/docs/guides/data-sources/#our-curated-misp).
        mitigations (list[MitigationDetail] | Unset): Deduplicated mitigations across all techniques
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        predictions (list[ThreatPrediction] | Unset): Threat predictions for the combined technique surface
        software (list[SoftwareDetail] | Unset): Malware/tools linked across all IOCs
        summary (None | str | Unset): AI-generated executive summary of the combined threat picture
        techniques (list[TechniqueDetail] | Unset): Deduplicated ATT&CK techniques across all IOCs
        total_sightings (int | Unset): Sum of sighting counts across matched attributes in the portfolio. Returned when
            `include` contains `sightings`; otherwise 0. Default: 0.
        warninglist_hits (list[AssessIOCPortfolioResponseWarninglistHitsItem] | Unset): Portfolio IOCs that matched a
            MISP warninglist (likely false positives or known-benign values). Returned when `include` contains
            `warninglist`. Each entry identifies the value, match status, warninglists, and categories.
    """

    campaigns: list[CampaignDetail] | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    galaxy_clusters: list[GalaxyClusterDetail] | Unset = UNSET
    groups: list[GroupDetail] | Unset = UNSET
    identifier_resolved: bool | None | Unset = UNSET
    indicators_assessed: int | Unset = 0
    misp_attributes: list[MISPAttribute] | Unset = UNSET
    misp_attributes_read_truncated: bool | Unset = False
    misp_attributes_total: int | Unset = 0
    misp_attributes_truncated: bool | Unset = False
    misp_events: list[MISPEvent] | Unset = UNSET
    misp_events_total: int | Unset = 0
    misp_events_truncated: bool | Unset = False
    misp_feed_hits: list[MISPFeedHit] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    predictions: list[ThreatPrediction] | Unset = UNSET
    software: list[SoftwareDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    total_sightings: int | Unset = 0
    warninglist_hits: list[AssessIOCPortfolioResponseWarninglistHitsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.assess_ioc_portfolio_response_warninglist_hits_item import (
            AssessIOCPortfolioResponseWarninglistHitsItem,  # noqa: PLC0415
        )
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.detection_detail import DetectionDetail  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.galaxy_cluster_detail import GalaxyClusterDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_event import MISPEvent  # noqa: PLC0415
        from ..models.misp_feed_hit import MISPFeedHit  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415

        campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.campaigns, Unset):
            campaigns = []
            for campaigns_item_data in self.campaigns:
                campaigns_item = campaigns_item_data.to_dict()
                campaigns.append(campaigns_item)

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

        groups: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = []
            for groups_item_data in self.groups:
                groups_item = groups_item_data.to_dict()
                groups.append(groups_item)

        identifier_resolved: bool | None | Unset
        if isinstance(self.identifier_resolved, Unset):
            identifier_resolved = UNSET
        else:
            identifier_resolved = self.identifier_resolved

        indicators_assessed = self.indicators_assessed

        misp_attributes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.misp_attributes, Unset):
            misp_attributes = []
            for misp_attributes_item_data in self.misp_attributes:
                misp_attributes_item = misp_attributes_item_data.to_dict()
                misp_attributes.append(misp_attributes_item)

        misp_attributes_read_truncated = self.misp_attributes_read_truncated

        misp_attributes_total = self.misp_attributes_total

        misp_attributes_truncated = self.misp_attributes_truncated

        misp_events: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.misp_events, Unset):
            misp_events = []
            for misp_events_item_data in self.misp_events:
                misp_events_item = misp_events_item_data.to_dict()
                misp_events.append(misp_events_item)

        misp_events_total = self.misp_events_total

        misp_events_truncated = self.misp_events_truncated

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

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        predictions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.predictions, Unset):
            predictions = []
            for predictions_item_data in self.predictions:
                predictions_item = predictions_item_data.to_dict()
                predictions.append(predictions_item)

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

        total_sightings = self.total_sightings

        warninglist_hits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.warninglist_hits, Unset):
            warninglist_hits = []
            for warninglist_hits_item_data in self.warninglist_hits:
                warninglist_hits_item = warninglist_hits_item_data.to_dict()
                warninglist_hits.append(warninglist_hits_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if campaigns is not UNSET:
            field_dict["campaigns"] = campaigns
        if defend is not UNSET:
            field_dict["defend"] = defend
        if detections is not UNSET:
            field_dict["detections"] = detections
        if errors is not UNSET:
            field_dict["errors"] = errors
        if galaxy_clusters is not UNSET:
            field_dict["galaxy_clusters"] = galaxy_clusters
        if groups is not UNSET:
            field_dict["groups"] = groups
        if identifier_resolved is not UNSET:
            field_dict["identifier_resolved"] = identifier_resolved
        if indicators_assessed is not UNSET:
            field_dict["indicators_assessed"] = indicators_assessed
        if misp_attributes is not UNSET:
            field_dict["misp_attributes"] = misp_attributes
        if misp_attributes_read_truncated is not UNSET:
            field_dict["misp_attributes_read_truncated"] = misp_attributes_read_truncated
        if misp_attributes_total is not UNSET:
            field_dict["misp_attributes_total"] = misp_attributes_total
        if misp_attributes_truncated is not UNSET:
            field_dict["misp_attributes_truncated"] = misp_attributes_truncated
        if misp_events is not UNSET:
            field_dict["misp_events"] = misp_events
        if misp_events_total is not UNSET:
            field_dict["misp_events_total"] = misp_events_total
        if misp_events_truncated is not UNSET:
            field_dict["misp_events_truncated"] = misp_events_truncated
        if misp_feed_hits is not UNSET:
            field_dict["misp_feed_hits"] = misp_feed_hits
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if software is not UNSET:
            field_dict["software"] = software
        if summary is not UNSET:
            field_dict["summary"] = summary
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if total_sightings is not UNSET:
            field_dict["total_sightings"] = total_sightings
        if warninglist_hits is not UNSET:
            field_dict["warninglist_hits"] = warninglist_hits

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.assess_ioc_portfolio_response_warninglist_hits_item import (
            AssessIOCPortfolioResponseWarninglistHitsItem,  # noqa: PLC0415
        )
        from ..models.campaign_detail import CampaignDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.detection_detail import DetectionDetail  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.galaxy_cluster_detail import GalaxyClusterDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.misp_attribute import MISPAttribute  # noqa: PLC0415
        from ..models.misp_event import MISPEvent  # noqa: PLC0415
        from ..models.misp_feed_hit import MISPFeedHit  # noqa: PLC0415
        from ..models.mitigation_detail import MitigationDetail  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.software_detail import SoftwareDetail  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415

        d = dict(src_dict)
        _campaigns = d.pop("campaigns", UNSET)
        campaigns: list[CampaignDetail] | Unset = UNSET
        if _campaigns is not UNSET:
            campaigns = []
            for campaigns_item_data in _campaigns:
                campaigns_item = CampaignDetail.from_dict(campaigns_item_data)

                campaigns.append(campaigns_item)

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

        _groups = d.pop("groups", UNSET)
        groups: list[GroupDetail] | Unset = UNSET
        if _groups is not UNSET:
            groups = []
            for groups_item_data in _groups:
                groups_item = GroupDetail.from_dict(groups_item_data)

                groups.append(groups_item)

        def _parse_identifier_resolved(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        identifier_resolved = _parse_identifier_resolved(d.pop("identifier_resolved", UNSET))

        indicators_assessed = d.pop("indicators_assessed", UNSET)

        _misp_attributes = d.pop("misp_attributes", UNSET)
        misp_attributes: list[MISPAttribute] | Unset = UNSET
        if _misp_attributes is not UNSET:
            misp_attributes = []
            for misp_attributes_item_data in _misp_attributes:
                misp_attributes_item = MISPAttribute.from_dict(misp_attributes_item_data)

                misp_attributes.append(misp_attributes_item)

        misp_attributes_read_truncated = d.pop("misp_attributes_read_truncated", UNSET)

        misp_attributes_total = d.pop("misp_attributes_total", UNSET)

        misp_attributes_truncated = d.pop("misp_attributes_truncated", UNSET)

        _misp_events = d.pop("misp_events", UNSET)
        misp_events: list[MISPEvent] | Unset = UNSET
        if _misp_events is not UNSET:
            misp_events = []
            for misp_events_item_data in _misp_events:
                misp_events_item = MISPEvent.from_dict(misp_events_item_data)

                misp_events.append(misp_events_item)

        misp_events_total = d.pop("misp_events_total", UNSET)

        misp_events_truncated = d.pop("misp_events_truncated", UNSET)

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

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        _predictions = d.pop("predictions", UNSET)
        predictions: list[ThreatPrediction] | Unset = UNSET
        if _predictions is not UNSET:
            predictions = []
            for predictions_item_data in _predictions:
                predictions_item = ThreatPrediction.from_dict(predictions_item_data)

                predictions.append(predictions_item)

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

        total_sightings = d.pop("total_sightings", UNSET)

        _warninglist_hits = d.pop("warninglist_hits", UNSET)
        warninglist_hits: list[AssessIOCPortfolioResponseWarninglistHitsItem] | Unset = UNSET
        if _warninglist_hits is not UNSET:
            warninglist_hits = []
            for warninglist_hits_item_data in _warninglist_hits:
                warninglist_hits_item = AssessIOCPortfolioResponseWarninglistHitsItem.from_dict(
                    warninglist_hits_item_data
                )

                warninglist_hits.append(warninglist_hits_item)

        assess_ioc_portfolio_response = cls(
            campaigns=campaigns,
            defend=defend,
            detections=detections,
            errors=errors,
            galaxy_clusters=galaxy_clusters,
            groups=groups,
            identifier_resolved=identifier_resolved,
            indicators_assessed=indicators_assessed,
            misp_attributes=misp_attributes,
            misp_attributes_read_truncated=misp_attributes_read_truncated,
            misp_attributes_total=misp_attributes_total,
            misp_attributes_truncated=misp_attributes_truncated,
            misp_events=misp_events,
            misp_events_total=misp_events_total,
            misp_events_truncated=misp_events_truncated,
            misp_feed_hits=misp_feed_hits,
            mitigations=mitigations,
            nist_controls=nist_controls,
            predictions=predictions,
            software=software,
            summary=summary,
            techniques=techniques,
            total_sightings=total_sightings,
            warninglist_hits=warninglist_hits,
        )

        assess_ioc_portfolio_response.additional_properties = d
        return assess_ioc_portfolio_response

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
