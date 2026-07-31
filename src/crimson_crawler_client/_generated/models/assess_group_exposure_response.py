from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.assess_group_exposure_response_navigator_type_0 import AssessGroupExposureResponseNavigatorType0
    from ..models.cve_mini_detail import CVEMiniDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.error_detail import ErrorDetail
    from ..models.group_detail import GroupDetail
    from ..models.location_detail import LocationDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.overlap_analysis import OverlapAnalysis
    from ..models.sector_detail import SectorDetail
    from ..models.technique_detail import TechniqueDetail
    from ..models.threat_prediction import ThreatPrediction


T = TypeVar("T", bound="AssessGroupExposureResponse")


@_attrs_define
class AssessGroupExposureResponse:
    """Aggregate technique surface across multiple threat groups.

    Attributes:
        cves (list[CVEMiniDetail] | Unset): CVEs exploitable by the combined technique set
        defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
            techniques
        errors (list[ErrorDetail] | Unset): Partial failure details
        groups (list[GroupDetail] | Unset): Group profiles for each assessed group
        locations (list[LocationDetail] | Unset): Regions where the assessed groups operate
        navigator (AssessGroupExposureResponseNavigatorType0 | None | Unset): Combined ATT&CK Navigator layer JSON for
            visualization in MITRE's Navigator tool
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        overlap_analysis (None | OverlapAnalysis | Unset): Technique overlap between the assessed groups
        predictions (list[ThreatPrediction] | Unset): Threat predictions for the combined technique surface
        sectors (list[SectorDetail] | Unset): Sectors targeted by the assessed groups
        summary (None | str | Unset): AI-generated summary of the combined threat exposure
        techniques (list[TechniqueDetail] | Unset): Deduplicated ATT&CK techniques across all groups
    """

    cves: list[CVEMiniDetail] | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    groups: list[GroupDetail] | Unset = UNSET
    locations: list[LocationDetail] | Unset = UNSET
    navigator: AssessGroupExposureResponseNavigatorType0 | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    overlap_analysis: None | OverlapAnalysis | Unset = UNSET
    predictions: list[ThreatPrediction] | Unset = UNSET
    sectors: list[SectorDetail] | Unset = UNSET
    summary: None | str | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.assess_group_exposure_response_navigator_type_0 import AssessGroupExposureResponseNavigatorType0
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.error_detail import ErrorDetail
        from ..models.group_detail import GroupDetail
        from ..models.location_detail import LocationDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.overlap_analysis import OverlapAnalysis
        from ..models.sector_detail import SectorDetail
        from ..models.technique_detail import TechniqueDetail
        from ..models.threat_prediction import ThreatPrediction

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

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        groups: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = []
            for groups_item_data in self.groups:
                groups_item = groups_item_data.to_dict()
                groups.append(groups_item)

        locations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.locations, Unset):
            locations = []
            for locations_item_data in self.locations:
                locations_item = locations_item_data.to_dict()
                locations.append(locations_item)

        navigator: dict[str, Any] | None | Unset
        if isinstance(self.navigator, Unset):
            navigator = UNSET
        elif isinstance(self.navigator, AssessGroupExposureResponseNavigatorType0):
            navigator = self.navigator.to_dict()
        else:
            navigator = self.navigator

        nist_controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nist_controls, Unset):
            nist_controls = []
            for nist_controls_item_data in self.nist_controls:
                nist_controls_item = nist_controls_item_data.to_dict()
                nist_controls.append(nist_controls_item)

        overlap_analysis: dict[str, Any] | None | Unset
        if isinstance(self.overlap_analysis, Unset):
            overlap_analysis = UNSET
        elif isinstance(self.overlap_analysis, OverlapAnalysis):
            overlap_analysis = self.overlap_analysis.to_dict()
        else:
            overlap_analysis = self.overlap_analysis

        predictions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.predictions, Unset):
            predictions = []
            for predictions_item_data in self.predictions:
                predictions_item = predictions_item_data.to_dict()
                predictions.append(predictions_item)

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

        techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = []
            for techniques_item_data in self.techniques:
                techniques_item = techniques_item_data.to_dict()
                techniques.append(techniques_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cves is not UNSET:
            field_dict["cves"] = cves
        if defend is not UNSET:
            field_dict["defend"] = defend
        if errors is not UNSET:
            field_dict["errors"] = errors
        if groups is not UNSET:
            field_dict["groups"] = groups
        if locations is not UNSET:
            field_dict["locations"] = locations
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if overlap_analysis is not UNSET:
            field_dict["overlap_analysis"] = overlap_analysis
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if sectors is not UNSET:
            field_dict["sectors"] = sectors
        if summary is not UNSET:
            field_dict["summary"] = summary
        if techniques is not UNSET:
            field_dict["techniques"] = techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.assess_group_exposure_response_navigator_type_0 import AssessGroupExposureResponseNavigatorType0
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.error_detail import ErrorDetail
        from ..models.group_detail import GroupDetail
        from ..models.location_detail import LocationDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.overlap_analysis import OverlapAnalysis
        from ..models.sector_detail import SectorDetail
        from ..models.technique_detail import TechniqueDetail
        from ..models.threat_prediction import ThreatPrediction

        d = dict(src_dict)
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

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _groups = d.pop("groups", UNSET)
        groups: list[GroupDetail] | Unset = UNSET
        if _groups is not UNSET:
            groups = []
            for groups_item_data in _groups:
                groups_item = GroupDetail.from_dict(groups_item_data)

                groups.append(groups_item)

        _locations = d.pop("locations", UNSET)
        locations: list[LocationDetail] | Unset = UNSET
        if _locations is not UNSET:
            locations = []
            for locations_item_data in _locations:
                locations_item = LocationDetail.from_dict(locations_item_data)

                locations.append(locations_item)

        def _parse_navigator(data: object) -> AssessGroupExposureResponseNavigatorType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                navigator_type_0 = AssessGroupExposureResponseNavigatorType0.from_dict(data)

                return navigator_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AssessGroupExposureResponseNavigatorType0 | None | Unset, data)

        navigator = _parse_navigator(d.pop("navigator", UNSET))

        _nist_controls = d.pop("nist_controls", UNSET)
        nist_controls: list[NistControlMapping] | Unset = UNSET
        if _nist_controls is not UNSET:
            nist_controls = []
            for nist_controls_item_data in _nist_controls:
                nist_controls_item = NistControlMapping.from_dict(nist_controls_item_data)

                nist_controls.append(nist_controls_item)

        def _parse_overlap_analysis(data: object) -> None | OverlapAnalysis | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                overlap_analysis_type_0 = OverlapAnalysis.from_dict(data)

                return overlap_analysis_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | OverlapAnalysis | Unset, data)

        overlap_analysis = _parse_overlap_analysis(d.pop("overlap_analysis", UNSET))

        _predictions = d.pop("predictions", UNSET)
        predictions: list[ThreatPrediction] | Unset = UNSET
        if _predictions is not UNSET:
            predictions = []
            for predictions_item_data in _predictions:
                predictions_item = ThreatPrediction.from_dict(predictions_item_data)

                predictions.append(predictions_item)

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

        _techniques = d.pop("techniques", UNSET)
        techniques: list[TechniqueDetail] | Unset = UNSET
        if _techniques is not UNSET:
            techniques = []
            for techniques_item_data in _techniques:
                techniques_item = TechniqueDetail.from_dict(techniques_item_data)

                techniques.append(techniques_item)

        assess_group_exposure_response = cls(
            cves=cves,
            defend=defend,
            errors=errors,
            groups=groups,
            locations=locations,
            navigator=navigator,
            nist_controls=nist_controls,
            overlap_analysis=overlap_analysis,
            predictions=predictions,
            sectors=sectors,
            summary=summary,
            techniques=techniques,
        )

        assess_group_exposure_response.additional_properties = d
        return assess_group_exposure_response

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
