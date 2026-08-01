from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.activity_summary import ActivitySummary
    from ..models.campaign_detail import CampaignDetail
    from ..models.cve_mini_detail import CVEMiniDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.enrich_group_response_navigator_type_0 import EnrichGroupResponseNavigatorType0
    from ..models.error_detail import ErrorDetail
    from ..models.group_detail import GroupDetail
    from ..models.knowledgebase_result import KnowledgebaseResult
    from ..models.location_detail import LocationDetail
    from ..models.misp_event import MISPEvent
    from ..models.mitigation_detail import MitigationDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.risk_profile import RiskProfile
    from ..models.sector_detail import SectorDetail
    from ..models.threat_prediction import ThreatPrediction
    from ..models.web_result import WebResult


T = TypeVar("T", bound="EnrichGroupResponse")


@_attrs_define
class EnrichGroupResponse:
    """Threat actor group enrichment with techniques and tooling.

    Attributes:
        activity_summary (ActivitySummary | None | Unset): Temporal activity overview with active/inactive status
        campaigns (list[CampaignDetail] | Unset): Threat campaigns that used the linked techniques
        cves (list[CVEMiniDetail] | Unset): CVEs exploitable by this group's techniques
        defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
            techniques
        detections (list[DetectionDetail] | Unset): Detection data sources and components for the linked techniques
        errors (list[ErrorDetail] | Unset): Partial failure details
        group (GroupDetail | None | Unset): Group profile (when looked up by ID)
        knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
        locations (list[LocationDetail] | Unset): Regions where this group operates
        misp (list[MISPEvent] | Unset): Threat events attributed to this group
        mitigations (list[MitigationDetail] | Unset): Defensive mitigations for the linked techniques
        navigator (EnrichGroupResponseNavigatorType0 | None | Unset): ATT&CK Navigator layer JSON for visualization in
            MITRE's Navigator tool
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        predictions (list[ThreatPrediction] | Unset): Threat predictions for the group's techniques
        risk_profile (None | RiskProfile | Unset): Damage potential based on exploitable CVEs
        search_results (list[GroupDetail] | Unset): Matching groups (when searched by text)
        sectors (list[SectorDetail] | Unset): Industry sectors targeted by this group
        summary (None | str | Unset): AI-generated summary of the threat group profile
        web (list[WebResult] | Unset): Web search results for this threat group
    """

    activity_summary: ActivitySummary | None | Unset = UNSET
    campaigns: list[CampaignDetail] | Unset = UNSET
    cves: list[CVEMiniDetail] | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    group: GroupDetail | None | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    locations: list[LocationDetail] | Unset = UNSET
    misp: list[MISPEvent] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    navigator: EnrichGroupResponseNavigatorType0 | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    predictions: list[ThreatPrediction] | Unset = UNSET
    risk_profile: None | RiskProfile | Unset = UNSET
    search_results: list[GroupDetail] | Unset = UNSET
    sectors: list[SectorDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    web: list[WebResult] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.activity_summary import ActivitySummary
        from ..models.campaign_detail import CampaignDetail
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.enrich_group_response_navigator_type_0 import EnrichGroupResponseNavigatorType0
        from ..models.error_detail import ErrorDetail
        from ..models.group_detail import GroupDetail
        from ..models.knowledgebase_result import KnowledgebaseResult
        from ..models.location_detail import LocationDetail
        from ..models.misp_event import MISPEvent
        from ..models.mitigation_detail import MitigationDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.risk_profile import RiskProfile
        from ..models.sector_detail import SectorDetail
        from ..models.threat_prediction import ThreatPrediction
        from ..models.web_result import WebResult

        activity_summary: dict[str, Any] | None | Unset
        if isinstance(self.activity_summary, Unset):
            activity_summary = UNSET
        elif isinstance(self.activity_summary, ActivitySummary):
            activity_summary = self.activity_summary.to_dict()
        else:
            activity_summary = self.activity_summary

        campaigns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.campaigns, Unset):
            campaigns = []
            for campaigns_item_data in self.campaigns:
                campaigns_item = campaigns_item_data.to_dict()
                campaigns.append(campaigns_item)

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

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        group: dict[str, Any] | None | Unset
        if isinstance(self.group, Unset):
            group = UNSET
        elif isinstance(self.group, GroupDetail):
            group = self.group.to_dict()
        else:
            group = self.group

        knowledgebase: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.knowledgebase, Unset):
            knowledgebase = []
            for knowledgebase_item_data in self.knowledgebase:
                knowledgebase_item = knowledgebase_item_data.to_dict()
                knowledgebase.append(knowledgebase_item)

        locations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.locations, Unset):
            locations = []
            for locations_item_data in self.locations:
                locations_item = locations_item_data.to_dict()
                locations.append(locations_item)

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
        elif isinstance(self.navigator, EnrichGroupResponseNavigatorType0):
            navigator = self.navigator.to_dict()
        else:
            navigator = self.navigator

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

        risk_profile: dict[str, Any] | None | Unset
        if isinstance(self.risk_profile, Unset):
            risk_profile = UNSET
        elif isinstance(self.risk_profile, RiskProfile):
            risk_profile = self.risk_profile.to_dict()
        else:
            risk_profile = self.risk_profile

        search_results: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.search_results, Unset):
            search_results = []
            for search_results_item_data in self.search_results:
                search_results_item = search_results_item_data.to_dict()
                search_results.append(search_results_item)

        sectors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.sectors, Unset):
            sectors = []
            for sectors_item_data in self.sectors:
                sectors_item = sectors_item_data.to_dict()
                sectors.append(sectors_item)

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        web: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.web, Unset):
            web = []
            for web_item_data in self.web:
                web_item = web_item_data.to_dict()
                web.append(web_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if activity_summary is not UNSET:
            field_dict["activity_summary"] = activity_summary
        if campaigns is not UNSET:
            field_dict["campaigns"] = campaigns
        if cves is not UNSET:
            field_dict["cves"] = cves
        if defend is not UNSET:
            field_dict["defend"] = defend
        if detections is not UNSET:
            field_dict["detections"] = detections
        if errors is not UNSET:
            field_dict["errors"] = errors
        if group is not UNSET:
            field_dict["group"] = group
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if locations is not UNSET:
            field_dict["locations"] = locations
        if misp is not UNSET:
            field_dict["misp"] = misp
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if risk_profile is not UNSET:
            field_dict["risk_profile"] = risk_profile
        if search_results is not UNSET:
            field_dict["search_results"] = search_results
        if sectors is not UNSET:
            field_dict["sectors"] = sectors
        if summary is not UNSET:
            field_dict["summary"] = summary
        if web is not UNSET:
            field_dict["web"] = web

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.activity_summary import ActivitySummary
        from ..models.campaign_detail import CampaignDetail
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.enrich_group_response_navigator_type_0 import EnrichGroupResponseNavigatorType0
        from ..models.error_detail import ErrorDetail
        from ..models.group_detail import GroupDetail
        from ..models.knowledgebase_result import KnowledgebaseResult
        from ..models.location_detail import LocationDetail
        from ..models.misp_event import MISPEvent
        from ..models.mitigation_detail import MitigationDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.risk_profile import RiskProfile
        from ..models.sector_detail import SectorDetail
        from ..models.threat_prediction import ThreatPrediction
        from ..models.web_result import WebResult

        d = dict(src_dict)

        def _parse_activity_summary(data: object) -> ActivitySummary | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                activity_summary_type_0 = ActivitySummary.from_dict(data)

                return activity_summary_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ActivitySummary | None | Unset, data)

        activity_summary = _parse_activity_summary(d.pop("activity_summary", UNSET))

        _campaigns = d.pop("campaigns", UNSET)
        campaigns: list[CampaignDetail] | Unset = UNSET
        if _campaigns is not UNSET:
            campaigns = []
            for campaigns_item_data in _campaigns:
                campaigns_item = CampaignDetail.from_dict(campaigns_item_data)

                campaigns.append(campaigns_item)

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

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

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

        _knowledgebase = d.pop("knowledgebase", UNSET)
        knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
        if _knowledgebase is not UNSET:
            knowledgebase = []
            for knowledgebase_item_data in _knowledgebase:
                knowledgebase_item = KnowledgebaseResult.from_dict(knowledgebase_item_data)

                knowledgebase.append(knowledgebase_item)

        _locations = d.pop("locations", UNSET)
        locations: list[LocationDetail] | Unset = UNSET
        if _locations is not UNSET:
            locations = []
            for locations_item_data in _locations:
                locations_item = LocationDetail.from_dict(locations_item_data)

                locations.append(locations_item)

        _misp = d.pop("misp", UNSET)
        misp: list[MISPEvent] | Unset = UNSET
        if _misp is not UNSET:
            misp = []
            for misp_item_data in _misp:
                misp_item = MISPEvent.from_dict(misp_item_data)

                misp.append(misp_item)

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[MitigationDetail] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = MitigationDetail.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        def _parse_navigator(data: object) -> EnrichGroupResponseNavigatorType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                navigator_type_0 = EnrichGroupResponseNavigatorType0.from_dict(data)

                return navigator_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnrichGroupResponseNavigatorType0 | None | Unset, data)

        navigator = _parse_navigator(d.pop("navigator", UNSET))

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

        def _parse_risk_profile(data: object) -> None | RiskProfile | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                risk_profile_type_0 = RiskProfile.from_dict(data)

                return risk_profile_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RiskProfile | Unset, data)

        risk_profile = _parse_risk_profile(d.pop("risk_profile", UNSET))

        _search_results = d.pop("search_results", UNSET)
        search_results: list[GroupDetail] | Unset = UNSET
        if _search_results is not UNSET:
            search_results = []
            for search_results_item_data in _search_results:
                search_results_item = GroupDetail.from_dict(search_results_item_data)

                search_results.append(search_results_item)

        _sectors = d.pop("sectors", UNSET)
        sectors: list[SectorDetail] | Unset = UNSET
        if _sectors is not UNSET:
            sectors = []
            for sectors_item_data in _sectors:
                sectors_item = SectorDetail.from_dict(sectors_item_data)

                sectors.append(sectors_item)

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        _web = d.pop("web", UNSET)
        web: list[WebResult] | Unset = UNSET
        if _web is not UNSET:
            web = []
            for web_item_data in _web:
                web_item = WebResult.from_dict(web_item_data)

                web.append(web_item)

        enrich_group_response = cls(
            activity_summary=activity_summary,
            campaigns=campaigns,
            cves=cves,
            defend=defend,
            detections=detections,
            errors=errors,
            group=group,
            knowledgebase=knowledgebase,
            locations=locations,
            misp=misp,
            mitigations=mitigations,
            navigator=navigator,
            nist_controls=nist_controls,
            predictions=predictions,
            risk_profile=risk_profile,
            search_results=search_results,
            sectors=sectors,
            summary=summary,
            web=web,
        )

        enrich_group_response.additional_properties = d
        return enrich_group_response

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
