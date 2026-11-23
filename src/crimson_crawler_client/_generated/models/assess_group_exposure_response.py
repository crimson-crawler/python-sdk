from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.assess_group_exposure_response_log_source_refs import AssessGroupExposureResponseLogSourceRefs
    from ..models.assess_group_exposure_response_navigator_type_0 import AssessGroupExposureResponseNavigatorType0
    from ..models.cve_mini_detail import CVEMiniDetail
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.error_detail import ErrorDetail
    from ..models.group_detail import GroupDetail
    from ..models.log_source import LogSource
    from ..models.nist_control_mapping import NistControlMapping
    from ..models.overlap_analysis import OverlapAnalysis
    from ..models.technique_detail import TechniqueDetail
    from ..models.threat_prediction import ThreatPrediction


T = TypeVar("T", bound="AssessGroupExposureResponse")


@_attrs_define
class AssessGroupExposureResponse:
    """Aggregate technique surface across multiple threat groups.

    Attributes:
        aggregate_over (int | Unset): Technique IDs covered by the tactic aggregate Default: 0.
        aggregate_total (int | Unset): Technique IDs considered for the tactic aggregate Default: 0.
        context_techniques_limit (int | Unset): Maximum technique IDs used for context fan-out Default: 0.
        context_techniques_selected (int | Unset): Technique IDs selected for bounded context; errors report failed
            reads Default: 0.
        cves (list[CVEMiniDetail] | Unset): CVEs exploitable by the combined technique set
        defend (list[D3FENDDetail] | Unset): D3FEND defensive techniques and countermeasures for the linked ATT&CK
            techniques. The default form omits each row's `description`, `aliases`, STIX `pattern` and `stix_id`; request
            include=['defend_full'] for them. The STIX licence marking (`object_marking_refs`) is kept in both forms.
        errors (list[ErrorDetail] | Unset): Partial failure details
        groups (list[GroupDetail] | Unset): Group profiles for each assessed group
        identifier_resolved (bool | None | Unset): Whether any requested group id resolved to a threat-actor profile.
            `false` means none of them were found, so the assessment below is empty for that reason rather than because the
            groups exist and have no technique footprint — the two were previously indistinguishable. `true` means at least
            one id resolved, NOT that all did. `null` when the request resolved its groups by `search` instead of by id (a
            legitimate no-match), or when no lookup was attempted.
        log_source_catalog (list[LogSource] | Unset): Deduplicated log sources for this page
        log_source_refs (AssessGroupExposureResponseLogSourceRefs | Unset): Technique ID to zero-based
            log_source_catalog indices, preserving source order
        navigator (AssessGroupExposureResponseNavigatorType0 | None | Unset): Combined ATT&CK Navigator layer JSON for
            visualization in MITRE's Navigator tool
        nist_controls (list[NistControlMapping] | Unset): NIST SP 800-53 rev 5 controls that mitigate the techniques on
            this response, via MITRE CTID. Pass-through static lookup; only populates when 'nist_controls' is in the request
            include set.
        overlap_analysis (None | OverlapAnalysis | Unset): Technique overlap between the assessed groups
        paging_incomplete (bool | Unset): True when a consumer could not collect every available page Default: False.
        predictions (list[ThreatPrediction] | Unset): Threat predictions for the combined technique surface
        snapshot_id (None | str | Unset): Snapshot identifier for later pages (expires after 30 minutes)
        summary (None | str | Unset): AI-generated summary of the combined threat exposure
        techniques (list[TechniqueDetail] | Unset): Deduplicated ATT&CK techniques across all groups
        techniques_next_offset (int | None | Unset): Offset for the next technique page
        techniques_total (int | Unset): Distinct discovered group technique IDs before paging Default: 0.
    """

    aggregate_over: int | Unset = 0
    aggregate_total: int | Unset = 0
    context_techniques_limit: int | Unset = 0
    context_techniques_selected: int | Unset = 0
    cves: list[CVEMiniDetail] | Unset = UNSET
    defend: list[D3FENDDetail] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    groups: list[GroupDetail] | Unset = UNSET
    identifier_resolved: bool | None | Unset = UNSET
    log_source_catalog: list[LogSource] | Unset = UNSET
    log_source_refs: AssessGroupExposureResponseLogSourceRefs | Unset = UNSET
    navigator: AssessGroupExposureResponseNavigatorType0 | None | Unset = UNSET
    nist_controls: list[NistControlMapping] | Unset = UNSET
    overlap_analysis: None | OverlapAnalysis | Unset = UNSET
    paging_incomplete: bool | Unset = False
    predictions: list[ThreatPrediction] | Unset = UNSET
    snapshot_id: None | str | Unset = UNSET
    summary: None | str | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    techniques_next_offset: int | None | Unset = UNSET
    techniques_total: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.assess_group_exposure_response_log_source_refs import (
            AssessGroupExposureResponseLogSourceRefs,  # noqa: PLC0415
        )
        from ..models.assess_group_exposure_response_navigator_type_0 import (
            AssessGroupExposureResponseNavigatorType0,  # noqa: PLC0415
        )
        from ..models.cve_mini_detail import CVEMiniDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.log_source import LogSource  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.overlap_analysis import OverlapAnalysis  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415

        aggregate_over = self.aggregate_over

        aggregate_total = self.aggregate_total

        context_techniques_limit = self.context_techniques_limit

        context_techniques_selected = self.context_techniques_selected

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

        identifier_resolved: bool | None | Unset
        if isinstance(self.identifier_resolved, Unset):
            identifier_resolved = UNSET
        else:
            identifier_resolved = self.identifier_resolved

        log_source_catalog: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.log_source_catalog, Unset):
            log_source_catalog = []
            for log_source_catalog_item_data in self.log_source_catalog:
                log_source_catalog_item = log_source_catalog_item_data.to_dict()
                log_source_catalog.append(log_source_catalog_item)

        log_source_refs: dict[str, Any] | Unset = UNSET
        if not isinstance(self.log_source_refs, Unset):
            log_source_refs = self.log_source_refs.to_dict()

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

        paging_incomplete = self.paging_incomplete

        predictions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.predictions, Unset):
            predictions = []
            for predictions_item_data in self.predictions:
                predictions_item = predictions_item_data.to_dict()
                predictions.append(predictions_item)

        snapshot_id: None | str | Unset
        if isinstance(self.snapshot_id, Unset):
            snapshot_id = UNSET
        else:
            snapshot_id = self.snapshot_id

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

        techniques_next_offset: int | None | Unset
        if isinstance(self.techniques_next_offset, Unset):
            techniques_next_offset = UNSET
        else:
            techniques_next_offset = self.techniques_next_offset

        techniques_total = self.techniques_total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if aggregate_over is not UNSET:
            field_dict["aggregate_over"] = aggregate_over
        if aggregate_total is not UNSET:
            field_dict["aggregate_total"] = aggregate_total
        if context_techniques_limit is not UNSET:
            field_dict["context_techniques_limit"] = context_techniques_limit
        if context_techniques_selected is not UNSET:
            field_dict["context_techniques_selected"] = context_techniques_selected
        if cves is not UNSET:
            field_dict["cves"] = cves
        if defend is not UNSET:
            field_dict["defend"] = defend
        if errors is not UNSET:
            field_dict["errors"] = errors
        if groups is not UNSET:
            field_dict["groups"] = groups
        if identifier_resolved is not UNSET:
            field_dict["identifier_resolved"] = identifier_resolved
        if log_source_catalog is not UNSET:
            field_dict["log_source_catalog"] = log_source_catalog
        if log_source_refs is not UNSET:
            field_dict["log_source_refs"] = log_source_refs
        if navigator is not UNSET:
            field_dict["navigator"] = navigator
        if nist_controls is not UNSET:
            field_dict["nist_controls"] = nist_controls
        if overlap_analysis is not UNSET:
            field_dict["overlap_analysis"] = overlap_analysis
        if paging_incomplete is not UNSET:
            field_dict["paging_incomplete"] = paging_incomplete
        if predictions is not UNSET:
            field_dict["predictions"] = predictions
        if snapshot_id is not UNSET:
            field_dict["snapshot_id"] = snapshot_id
        if summary is not UNSET:
            field_dict["summary"] = summary
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if techniques_next_offset is not UNSET:
            field_dict["techniques_next_offset"] = techniques_next_offset
        if techniques_total is not UNSET:
            field_dict["techniques_total"] = techniques_total

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.assess_group_exposure_response_log_source_refs import (
            AssessGroupExposureResponseLogSourceRefs,  # noqa: PLC0415
        )
        from ..models.assess_group_exposure_response_navigator_type_0 import (
            AssessGroupExposureResponseNavigatorType0,  # noqa: PLC0415
        )
        from ..models.cve_mini_detail import CVEMiniDetail  # noqa: PLC0415
        from ..models.d3fend_detail import D3FENDDetail  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.group_detail import GroupDetail  # noqa: PLC0415
        from ..models.log_source import LogSource  # noqa: PLC0415
        from ..models.nist_control_mapping import NistControlMapping  # noqa: PLC0415
        from ..models.overlap_analysis import OverlapAnalysis  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415
        from ..models.threat_prediction import ThreatPrediction  # noqa: PLC0415

        d = dict(src_dict)
        aggregate_over = d.pop("aggregate_over", UNSET)

        aggregate_total = d.pop("aggregate_total", UNSET)

        context_techniques_limit = d.pop("context_techniques_limit", UNSET)

        context_techniques_selected = d.pop("context_techniques_selected", UNSET)

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

        def _parse_identifier_resolved(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        identifier_resolved = _parse_identifier_resolved(d.pop("identifier_resolved", UNSET))

        _log_source_catalog = d.pop("log_source_catalog", UNSET)
        log_source_catalog: list[LogSource] | Unset = UNSET
        if _log_source_catalog is not UNSET:
            log_source_catalog = []
            for log_source_catalog_item_data in _log_source_catalog:
                log_source_catalog_item = LogSource.from_dict(log_source_catalog_item_data)

                log_source_catalog.append(log_source_catalog_item)

        _log_source_refs = d.pop("log_source_refs", UNSET)
        log_source_refs: AssessGroupExposureResponseLogSourceRefs | Unset
        if isinstance(_log_source_refs, Unset):
            log_source_refs = UNSET
        else:
            log_source_refs = AssessGroupExposureResponseLogSourceRefs.from_dict(_log_source_refs)

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

        paging_incomplete = d.pop("paging_incomplete", UNSET)

        _predictions = d.pop("predictions", UNSET)
        predictions: list[ThreatPrediction] | Unset = UNSET
        if _predictions is not UNSET:
            predictions = []
            for predictions_item_data in _predictions:
                predictions_item = ThreatPrediction.from_dict(predictions_item_data)

                predictions.append(predictions_item)

        def _parse_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        snapshot_id = _parse_snapshot_id(d.pop("snapshot_id", UNSET))

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

        def _parse_techniques_next_offset(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        techniques_next_offset = _parse_techniques_next_offset(d.pop("techniques_next_offset", UNSET))

        techniques_total = d.pop("techniques_total", UNSET)

        assess_group_exposure_response = cls(
            aggregate_over=aggregate_over,
            aggregate_total=aggregate_total,
            context_techniques_limit=context_techniques_limit,
            context_techniques_selected=context_techniques_selected,
            cves=cves,
            defend=defend,
            errors=errors,
            groups=groups,
            identifier_resolved=identifier_resolved,
            log_source_catalog=log_source_catalog,
            log_source_refs=log_source_refs,
            navigator=navigator,
            nist_controls=nist_controls,
            overlap_analysis=overlap_analysis,
            paging_incomplete=paging_incomplete,
            predictions=predictions,
            snapshot_id=snapshot_id,
            summary=summary,
            techniques=techniques,
            techniques_next_offset=techniques_next_offset,
            techniques_total=techniques_total,
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
