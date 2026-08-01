from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.assess_technique_coverage_response_navigator_type_0 import (
        AssessTechniqueCoverageResponseNavigatorType0,
    )
    from ..models.coverage_score import CoverageScore
    from ..models.cve_mini_detail import CVEMiniDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.error_detail import ErrorDetail
    from ..models.mitigation_detail import MitigationDetail
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.priority_gap import PriorityGap
    from ..models.technique_detail import TechniqueDetail
    from ..models.threat_prediction import ThreatPrediction


T = TypeVar("T", bound="AssessTechniqueCoverageResponse")


@_attrs_define
class AssessTechniqueCoverageResponse:
    """Batch technique assessment - mitigations, detection methods, and threat predictions.

    Attributes:
        coverage_score (CoverageScore | None | Unset): Mitigation and detection coverage analysis
        cves (list[CVEMiniDetail] | Unset): CVEs linked to the assessed techniques
        defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
            techniques
        detections (list[DetectionDetail] | Unset): Aggregated detection methods across all assessed techniques
        errors (list[ErrorDetail] | Unset): Partial failure details
        mitigations (list[MitigationDetail] | Unset): Aggregated mitigations across all assessed techniques
        navigator (AssessTechniqueCoverageResponseNavigatorType0 | None | Unset): ATT&CK Navigator layer JSON for
            visualization in MITRE's Navigator tool
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        predictions (list[ThreatPrediction] | Unset): Threat predictions for each assessed technique
        priority_gaps (list[PriorityGap] | Unset): Uncovered techniques ranked by exposure impact
        summary (None | str | Unset): AI-generated narrative of coverage gaps, mitigations, and high-priority techniques
        techniques (list[TechniqueDetail] | Unset): Full technique details for each assessed technique
    """

    coverage_score: CoverageScore | None | Unset = UNSET
    cves: list[CVEMiniDetail] | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    navigator: AssessTechniqueCoverageResponseNavigatorType0 | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    predictions: list[ThreatPrediction] | Unset = UNSET
    priority_gaps: list[PriorityGap] | Unset = UNSET
    summary: None | str | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.assess_technique_coverage_response_navigator_type_0 import (
            AssessTechniqueCoverageResponseNavigatorType0,
        )
        from ..models.coverage_score import CoverageScore
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.error_detail import ErrorDetail
        from ..models.mitigation_detail import MitigationDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.priority_gap import PriorityGap
        from ..models.technique_detail import TechniqueDetail
        from ..models.threat_prediction import ThreatPrediction

        coverage_score: dict[str, Any] | None | Unset
        if isinstance(self.coverage_score, Unset):
            coverage_score = UNSET
        elif isinstance(self.coverage_score, CoverageScore):
            coverage_score = self.coverage_score.to_dict()
        else:
            coverage_score = self.coverage_score

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

        mitigations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = []
            for mitigations_item_data in self.mitigations:
                mitigations_item = mitigations_item_data.to_dict()
                mitigations.append(mitigations_item)

        navigator: dict[str, Any] | None | Unset
        if isinstance(self.navigator, Unset):
            navigator = UNSET
        elif isinstance(self.navigator, AssessTechniqueCoverageResponseNavigatorType0):
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

        priority_gaps: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.priority_gaps, Unset):
            priority_gaps = []
            for priority_gaps_item_data in self.priority_gaps:
                priority_gaps_item = priority_gaps_item_data.to_dict()
                priority_gaps.append(priority_gaps_item)

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
        if coverage_score is not UNSET:
            field_dict["coverage_score"] = coverage_score
        if cves is not UNSET:
            field_dict["cves"] = cves
        if defend is not UNSET:
            field_dict["defend"] = defend
        if detections is not UNSET:
            field_dict["detections"] = detections
        if errors is not UNSET:
            field_dict["errors"] = errors
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if priority_gaps is not UNSET:
            field_dict["priority_gaps"] = priority_gaps
        if summary is not UNSET:
            field_dict["summary"] = summary
        if techniques is not UNSET:
            field_dict["techniques"] = techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.assess_technique_coverage_response_navigator_type_0 import (
            AssessTechniqueCoverageResponseNavigatorType0,
        )
        from ..models.coverage_score import CoverageScore
        from ..models.cve_mini_detail import CVEMiniDetail
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.error_detail import ErrorDetail
        from ..models.mitigation_detail import MitigationDetail
        from ..models.nist_control_mapping import NistControlMapping
        from ..models.priority_gap import PriorityGap
        from ..models.technique_detail import TechniqueDetail
        from ..models.threat_prediction import ThreatPrediction

        d = dict(src_dict)

        def _parse_coverage_score(data: object) -> CoverageScore | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                coverage_score_type_0 = CoverageScore.from_dict(data)

                return coverage_score_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CoverageScore | None | Unset, data)

        coverage_score = _parse_coverage_score(d.pop("coverage_score", UNSET))

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

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[MitigationDetail] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = MitigationDetail.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        def _parse_navigator(data: object) -> AssessTechniqueCoverageResponseNavigatorType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                navigator_type_0 = AssessTechniqueCoverageResponseNavigatorType0.from_dict(data)

                return navigator_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AssessTechniqueCoverageResponseNavigatorType0 | None | Unset, data)

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

        _priority_gaps = d.pop("priority_gaps", UNSET)
        priority_gaps: list[PriorityGap] | Unset = UNSET
        if _priority_gaps is not UNSET:
            priority_gaps = []
            for priority_gaps_item_data in _priority_gaps:
                priority_gaps_item = PriorityGap.from_dict(priority_gaps_item_data)

                priority_gaps.append(priority_gaps_item)

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

        assess_technique_coverage_response = cls(
            coverage_score=coverage_score,
            cves=cves,
            defend=defend,
            detections=detections,
            errors=errors,
            mitigations=mitigations,
            navigator=navigator,
            nist_controls=nist_controls,
            predictions=predictions,
            priority_gaps=priority_gaps,
            summary=summary,
            techniques=techniques,
        )

        assess_technique_coverage_response.additional_properties = d
        return assess_technique_coverage_response

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
