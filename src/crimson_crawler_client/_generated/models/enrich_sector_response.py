from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.campaign_detail import CampaignDetail
    from ..models.cve_mini_detail import CVEMiniDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.enrich_sector_response_navigator_type_0 import EnrichSectorResponseNavigatorType0
    from ..models.error_detail import ErrorDetail
    from ..models.knowledgebase_result import KnowledgebaseResult
    from ..models.location_detail import LocationDetail
    from ..models.mitigation_detail import MitigationDetail
    from ..models.sector_detail import SectorDetail
    from ..models.software_detail import SoftwareDetail
    from ..models.threat_prediction import ThreatPrediction
    from ..models.web_result import WebResult


T = TypeVar("T", bound="EnrichSectorResponse")


@_attrs_define
class EnrichSectorResponse:
    """Industry sector threat landscape - groups, techniques, and defensive context.

    Attributes:
        campaigns (list[CampaignDetail] | Unset): Threat campaigns that used the linked techniques
        cves (list[CVEMiniDetail] | Unset): CVEs linked to techniques targeting this sector
        defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
            techniques
        detections (list[DetectionDetail] | Unset): Detection data sources and components for the linked techniques
        errors (list[ErrorDetail] | Unset): Partial failure details
        knowledgebase (list[KnowledgebaseResult] | Unset): Related intelligence from the knowledge base
        locations (list[LocationDetail] | Unset): Regions associated with this sector's threat landscape
        mitigations (list[MitigationDetail] | Unset): Defensive mitigations for the linked techniques
        navigator (EnrichSectorResponseNavigatorType0 | None | Unset): ATT&CK Navigator layer JSON for visualization in
            MITRE's Navigator tool
        predictions (list[ThreatPrediction] | Unset): Threat predictions for techniques targeting this sector
        search_results (list[SectorDetail] | Unset): Matching sectors (when searched by text)
        sector (None | SectorDetail | Unset): Sector threat profile (when looked up by ID)
        software (list[SoftwareDetail] | Unset): Malware and tools that employ the linked techniques
        summary (None | str | Unset): AI-generated summary of the sector threat profile
        web (list[WebResult] | Unset): Web search results for this sector's threat landscape
    """

    campaigns: list[CampaignDetail] | Unset = UNSET
    cves: list[CVEMiniDetail] | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    knowledgebase: list[KnowledgebaseResult] | Unset = UNSET
    locations: list[LocationDetail] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    navigator: EnrichSectorResponseNavigatorType0 | None | Unset = UNSET
    predictions: list[ThreatPrediction] | Unset = UNSET
    search_results: list[SectorDetail] | Unset = UNSET
    sector: None | SectorDetail | Unset = UNSET
    software: list[SoftwareDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    web: list[WebResult] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.campaign_detail import CampaignDetail
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.enrich_sector_response_navigator_type_0 import EnrichSectorResponseNavigatorType0
        from ..models.error_detail import ErrorDetail
        from ..models.knowledgebase_result import KnowledgebaseResult
        from ..models.location_detail import LocationDetail
        from ..models.mitigation_detail import MitigationDetail
        from ..models.sector_detail import SectorDetail
        from ..models.software_detail import SoftwareDetail
        from ..models.threat_prediction import ThreatPrediction
        from ..models.web_result import WebResult

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

        mitigations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = []
            for mitigations_item_data in self.mitigations:
                mitigations_item = mitigations_item_data.to_dict()
                mitigations.append(mitigations_item)

        navigator: dict[str, Any] | None | Unset
        if isinstance(self.navigator, Unset):
            navigator = UNSET
        elif isinstance(self.navigator, EnrichSectorResponseNavigatorType0):
            navigator = self.navigator.to_dict()
        else:
            navigator = self.navigator

        predictions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.predictions, Unset):
            predictions = []
            for predictions_item_data in self.predictions:
                predictions_item = predictions_item_data.to_dict()
                predictions.append(predictions_item)

        search_results: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.search_results, Unset):
            search_results = []
            for search_results_item_data in self.search_results:
                search_results_item = search_results_item_data.to_dict()
                search_results.append(search_results_item)

        sector: dict[str, Any] | None | Unset
        if isinstance(self.sector, Unset):
            sector = UNSET
        elif isinstance(self.sector, SectorDetail):
            sector = self.sector.to_dict()
        else:
            sector = self.sector

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

        web: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.web, Unset):
            web = []
            for web_item_data in self.web:
                web_item = web_item_data.to_dict()
                web.append(web_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
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
        if knowledgebase is not UNSET:
            field_dict["knowledgebase"] = knowledgebase
        if locations is not UNSET:
            field_dict["locations"] = locations
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if search_results is not UNSET:
            field_dict["search_results"] = search_results
        if sector is not UNSET:
            field_dict["sector"] = sector
        if software is not UNSET:
            field_dict["software"] = software
        if summary is not UNSET:
            field_dict["summary"] = summary
        if web is not UNSET:
            field_dict["web"] = web

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.campaign_detail import CampaignDetail
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.enrich_sector_response_navigator_type_0 import EnrichSectorResponseNavigatorType0
        from ..models.error_detail import ErrorDetail
        from ..models.knowledgebase_result import KnowledgebaseResult
        from ..models.location_detail import LocationDetail
        from ..models.mitigation_detail import MitigationDetail
        from ..models.sector_detail import SectorDetail
        from ..models.software_detail import SoftwareDetail
        from ..models.threat_prediction import ThreatPrediction
        from ..models.web_result import WebResult

        d = dict(src_dict)
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

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[MitigationDetail] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = MitigationDetail.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        def _parse_navigator(data: object) -> EnrichSectorResponseNavigatorType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                navigator_type_0 = EnrichSectorResponseNavigatorType0.from_dict(data)

                return navigator_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnrichSectorResponseNavigatorType0 | None | Unset, data)

        navigator = _parse_navigator(d.pop("navigator", UNSET))

        _predictions = d.pop("predictions", UNSET)
        predictions: list[ThreatPrediction] | Unset = UNSET
        if _predictions is not UNSET:
            predictions = []
            for predictions_item_data in _predictions:
                predictions_item = ThreatPrediction.from_dict(predictions_item_data)

                predictions.append(predictions_item)

        _search_results = d.pop("search_results", UNSET)
        search_results: list[SectorDetail] | Unset = UNSET
        if _search_results is not UNSET:
            search_results = []
            for search_results_item_data in _search_results:
                search_results_item = SectorDetail.from_dict(search_results_item_data)

                search_results.append(search_results_item)

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

        _web = d.pop("web", UNSET)
        web: list[WebResult] | Unset = UNSET
        if _web is not UNSET:
            web = []
            for web_item_data in _web:
                web_item = WebResult.from_dict(web_item_data)

                web.append(web_item)

        enrich_sector_response = cls(
            campaigns=campaigns,
            cves=cves,
            defend=defend,
            detections=detections,
            errors=errors,
            knowledgebase=knowledgebase,
            locations=locations,
            mitigations=mitigations,
            navigator=navigator,
            predictions=predictions,
            search_results=search_results,
            sector=sector,
            software=software,
            summary=summary,
            web=web,
        )

        enrich_sector_response.additional_properties = d
        return enrich_sector_response

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
