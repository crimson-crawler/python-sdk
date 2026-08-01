from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.artifact_enrichment_meta import ArtifactEnrichmentMeta
    from ..models.artifact_enrichment_reference import ArtifactEnrichmentReference
    from ..models.artifact_enrichment_report_exports import ArtifactEnrichmentReportExports
    from ..models.artifact_enrichment_report_rollups_type_0 import ArtifactEnrichmentReportRollupsType0
    from ..models.attack_path import AttackPath
    from ..models.coverage_gap import CoverageGap
    from ..models.defense_triad import DefenseTriad
    from ..models.detection_opportunity import DetectionOpportunity
    from ..models.error_detail import ErrorDetail
    from ..models.key_judgment import KeyJudgment
    from ..models.prioritized_action import PrioritizedAction
    from ..models.source_confidence_statement import SourceConfidenceStatement
    from ..models.source_corroboration import SourceCorroboration


T = TypeVar("T", bound="ArtifactEnrichmentReport")


@_attrs_define
class ArtifactEnrichmentReport:
    """The canonical Crimson Enricher report — one object behind every screen and export.

    Fully deterministic: SSVC decisions, scores, grades, prioritized actions, defense
    triads, attack paths, key judgments, and the optional `narrative` are composed from structured
    signals without generative inference.

        Attributes:
            meta (ArtifactEnrichmentMeta): Report metadata.
            attack_paths (list[AttackPath] | Unset): Kill-chain-ordered technique sequences
            bluf (None | str | Unset): ≤2-sentence bottom-line (deterministic: counts + top action)
            coverage_gaps (list[CoverageGap] | Unset): Structured 'what we DON'T know' panel — analyst-facing coverage gaps
                derived from per-reference structured signals (missing techniques, KEV records, EPSS data, low corroboration,
                empty chain walks). Each entry lists the affected reference IDs.
            defensive_summary (list[DefenseTriad] | Unset): Deduplicated detect/mitigate/counter triads across all
                references
            detection_opportunities (list[DetectionOpportunity] | Unset): Flat detection opportunities from resolved
                techniques (back-compat for exports)
            errors (list[ErrorDetail] | Unset): Report-level partial-failure details
            exports (ArtifactEnrichmentReportExports | Unset): Serialized export payloads keyed by format
            key_judgments (list[KeyJudgment] | Unset): Deterministic finished-intel key judgments
            narrative (None | str | Unset): Deterministic executive narration (only with include=narrative)
            prioritized_actions (list[PrioritizedAction] | Unset): Ranked worklist (SSVC band + score + SLA), most urgent
                first
            references (list[ArtifactEnrichmentReference] | Unset): Per-reference enrichment + SSVC + scoring
            rollups (ArtifactEnrichmentReportRollupsType0 | None | Unset): Cross-reference assess/* rollups for collections
            source_confidence_statement (None | SourceConfidenceStatement | Unset): Aggregate provenance + confidence
                statement
            source_corroboration (None | SourceCorroboration | Unset): Per-source contribution matrix + analytic-confidence
                rollup
    """

    meta: ArtifactEnrichmentMeta
    attack_paths: list[AttackPath] | Unset = UNSET
    bluf: None | str | Unset = UNSET
    coverage_gaps: list[CoverageGap] | Unset = UNSET
    defensive_summary: list[DefenseTriad] | Unset = UNSET
    detection_opportunities: list[DetectionOpportunity] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    exports: ArtifactEnrichmentReportExports | Unset = UNSET
    key_judgments: list[KeyJudgment] | Unset = UNSET
    narrative: None | str | Unset = UNSET
    prioritized_actions: list[PrioritizedAction] | Unset = UNSET
    references: list[ArtifactEnrichmentReference] | Unset = UNSET
    rollups: ArtifactEnrichmentReportRollupsType0 | None | Unset = UNSET
    source_confidence_statement: None | SourceConfidenceStatement | Unset = UNSET
    source_corroboration: None | SourceCorroboration | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.artifact_enrichment_meta import ArtifactEnrichmentMeta
        from ..models.artifact_enrichment_reference import ArtifactEnrichmentReference
        from ..models.artifact_enrichment_report_exports import ArtifactEnrichmentReportExports
        from ..models.artifact_enrichment_report_rollups_type_0 import ArtifactEnrichmentReportRollupsType0
        from ..models.attack_path import AttackPath
        from ..models.coverage_gap import CoverageGap
        from ..models.defense_triad import DefenseTriad
        from ..models.detection_opportunity import DetectionOpportunity
        from ..models.error_detail import ErrorDetail
        from ..models.key_judgment import KeyJudgment
        from ..models.prioritized_action import PrioritizedAction
        from ..models.source_confidence_statement import SourceConfidenceStatement
        from ..models.source_corroboration import SourceCorroboration

        meta = self.meta.to_dict()

        attack_paths: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.attack_paths, Unset):
            attack_paths = []
            for attack_paths_item_data in self.attack_paths:
                attack_paths_item = attack_paths_item_data.to_dict()
                attack_paths.append(attack_paths_item)

        bluf: None | str | Unset
        if isinstance(self.bluf, Unset):
            bluf = UNSET
        else:
            bluf = self.bluf

        coverage_gaps: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.coverage_gaps, Unset):
            coverage_gaps = []
            for coverage_gaps_item_data in self.coverage_gaps:
                coverage_gaps_item = coverage_gaps_item_data.to_dict()
                coverage_gaps.append(coverage_gaps_item)

        defensive_summary: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.defensive_summary, Unset):
            defensive_summary = []
            for defensive_summary_item_data in self.defensive_summary:
                defensive_summary_item = defensive_summary_item_data.to_dict()
                defensive_summary.append(defensive_summary_item)

        detection_opportunities: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.detection_opportunities, Unset):
            detection_opportunities = []
            for detection_opportunities_item_data in self.detection_opportunities:
                detection_opportunities_item = detection_opportunities_item_data.to_dict()
                detection_opportunities.append(detection_opportunities_item)

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        exports: dict[str, Any] | Unset = UNSET
        if not isinstance(self.exports, Unset):
            exports = self.exports.to_dict()

        key_judgments: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.key_judgments, Unset):
            key_judgments = []
            for key_judgments_item_data in self.key_judgments:
                key_judgments_item = key_judgments_item_data.to_dict()
                key_judgments.append(key_judgments_item)

        narrative: None | str | Unset
        if isinstance(self.narrative, Unset):
            narrative = UNSET
        else:
            narrative = self.narrative

        prioritized_actions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.prioritized_actions, Unset):
            prioritized_actions = []
            for prioritized_actions_item_data in self.prioritized_actions:
                prioritized_actions_item = prioritized_actions_item_data.to_dict()
                prioritized_actions.append(prioritized_actions_item)

        references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = []
            for references_item_data in self.references:
                references_item = references_item_data.to_dict()
                references.append(references_item)

        rollups: dict[str, Any] | None | Unset
        if isinstance(self.rollups, Unset):
            rollups = UNSET
        elif isinstance(self.rollups, ArtifactEnrichmentReportRollupsType0):
            rollups = self.rollups.to_dict()
        else:
            rollups = self.rollups

        source_confidence_statement: dict[str, Any] | None | Unset
        if isinstance(self.source_confidence_statement, Unset):
            source_confidence_statement = UNSET
        elif isinstance(self.source_confidence_statement, SourceConfidenceStatement):
            source_confidence_statement = self.source_confidence_statement.to_dict()
        else:
            source_confidence_statement = self.source_confidence_statement

        source_corroboration: dict[str, Any] | None | Unset
        if isinstance(self.source_corroboration, Unset):
            source_corroboration = UNSET
        elif isinstance(self.source_corroboration, SourceCorroboration):
            source_corroboration = self.source_corroboration.to_dict()
        else:
            source_corroboration = self.source_corroboration

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "meta": meta,
            }
        )
        if attack_paths is not UNSET:
            field_dict["attack_paths"] = attack_paths
        if bluf is not UNSET:
            field_dict["bluf"] = bluf
        if coverage_gaps is not UNSET:
            field_dict["coverage_gaps"] = coverage_gaps
        if defensive_summary is not UNSET:
            field_dict["defensive_summary"] = defensive_summary
        if detection_opportunities is not UNSET:
            field_dict["detection_opportunities"] = detection_opportunities
        if errors is not UNSET:
            field_dict["errors"] = errors
        if exports is not UNSET:
            field_dict["exports"] = exports
        if key_judgments is not UNSET:
            field_dict["key_judgments"] = key_judgments
        if narrative is not UNSET:
            field_dict["narrative"] = narrative
        if prioritized_actions is not UNSET:
            field_dict["prioritized_actions"] = prioritized_actions
        if references is not UNSET:
            field_dict["references"] = references
        if rollups is not UNSET:
            field_dict["rollups"] = rollups
        if source_confidence_statement is not UNSET:
            field_dict["source_confidence_statement"] = source_confidence_statement
        if source_corroboration is not UNSET:
            field_dict["source_corroboration"] = source_corroboration

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.artifact_enrichment_meta import ArtifactEnrichmentMeta
        from ..models.artifact_enrichment_reference import ArtifactEnrichmentReference
        from ..models.artifact_enrichment_report_exports import ArtifactEnrichmentReportExports
        from ..models.artifact_enrichment_report_rollups_type_0 import ArtifactEnrichmentReportRollupsType0
        from ..models.attack_path import AttackPath
        from ..models.coverage_gap import CoverageGap
        from ..models.defense_triad import DefenseTriad
        from ..models.detection_opportunity import DetectionOpportunity
        from ..models.error_detail import ErrorDetail
        from ..models.key_judgment import KeyJudgment
        from ..models.prioritized_action import PrioritizedAction
        from ..models.source_confidence_statement import SourceConfidenceStatement
        from ..models.source_corroboration import SourceCorroboration

        d = dict(src_dict)
        meta = ArtifactEnrichmentMeta.from_dict(d.pop("meta"))

        _attack_paths = d.pop("attack_paths", UNSET)
        attack_paths: list[AttackPath] | Unset = UNSET
        if _attack_paths is not UNSET:
            attack_paths = []
            for attack_paths_item_data in _attack_paths:
                attack_paths_item = AttackPath.from_dict(attack_paths_item_data)

                attack_paths.append(attack_paths_item)

        def _parse_bluf(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        bluf = _parse_bluf(d.pop("bluf", UNSET))

        _coverage_gaps = d.pop("coverage_gaps", UNSET)
        coverage_gaps: list[CoverageGap] | Unset = UNSET
        if _coverage_gaps is not UNSET:
            coverage_gaps = []
            for coverage_gaps_item_data in _coverage_gaps:
                coverage_gaps_item = CoverageGap.from_dict(coverage_gaps_item_data)

                coverage_gaps.append(coverage_gaps_item)

        _defensive_summary = d.pop("defensive_summary", UNSET)
        defensive_summary: list[DefenseTriad] | Unset = UNSET
        if _defensive_summary is not UNSET:
            defensive_summary = []
            for defensive_summary_item_data in _defensive_summary:
                defensive_summary_item = DefenseTriad.from_dict(defensive_summary_item_data)

                defensive_summary.append(defensive_summary_item)

        _detection_opportunities = d.pop("detection_opportunities", UNSET)
        detection_opportunities: list[DetectionOpportunity] | Unset = UNSET
        if _detection_opportunities is not UNSET:
            detection_opportunities = []
            for detection_opportunities_item_data in _detection_opportunities:
                detection_opportunities_item = DetectionOpportunity.from_dict(detection_opportunities_item_data)

                detection_opportunities.append(detection_opportunities_item)

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _exports = d.pop("exports", UNSET)
        exports: ArtifactEnrichmentReportExports | Unset
        if isinstance(_exports, Unset):
            exports = UNSET
        else:
            exports = ArtifactEnrichmentReportExports.from_dict(_exports)

        _key_judgments = d.pop("key_judgments", UNSET)
        key_judgments: list[KeyJudgment] | Unset = UNSET
        if _key_judgments is not UNSET:
            key_judgments = []
            for key_judgments_item_data in _key_judgments:
                key_judgments_item = KeyJudgment.from_dict(key_judgments_item_data)

                key_judgments.append(key_judgments_item)

        def _parse_narrative(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        narrative = _parse_narrative(d.pop("narrative", UNSET))

        _prioritized_actions = d.pop("prioritized_actions", UNSET)
        prioritized_actions: list[PrioritizedAction] | Unset = UNSET
        if _prioritized_actions is not UNSET:
            prioritized_actions = []
            for prioritized_actions_item_data in _prioritized_actions:
                prioritized_actions_item = PrioritizedAction.from_dict(prioritized_actions_item_data)

                prioritized_actions.append(prioritized_actions_item)

        _references = d.pop("references", UNSET)
        references: list[ArtifactEnrichmentReference] | Unset = UNSET
        if _references is not UNSET:
            references = []
            for references_item_data in _references:
                references_item = ArtifactEnrichmentReference.from_dict(references_item_data)

                references.append(references_item)

        def _parse_rollups(data: object) -> ArtifactEnrichmentReportRollupsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                rollups_type_0 = ArtifactEnrichmentReportRollupsType0.from_dict(data)

                return rollups_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ArtifactEnrichmentReportRollupsType0 | None | Unset, data)

        rollups = _parse_rollups(d.pop("rollups", UNSET))

        def _parse_source_confidence_statement(data: object) -> None | SourceConfidenceStatement | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                source_confidence_statement_type_0 = SourceConfidenceStatement.from_dict(data)

                return source_confidence_statement_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SourceConfidenceStatement | Unset, data)

        source_confidence_statement = _parse_source_confidence_statement(d.pop("source_confidence_statement", UNSET))

        def _parse_source_corroboration(data: object) -> None | SourceCorroboration | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                source_corroboration_type_0 = SourceCorroboration.from_dict(data)

                return source_corroboration_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SourceCorroboration | Unset, data)

        source_corroboration = _parse_source_corroboration(d.pop("source_corroboration", UNSET))

        artifact_enrichment_report = cls(
            meta=meta,
            attack_paths=attack_paths,
            bluf=bluf,
            coverage_gaps=coverage_gaps,
            defensive_summary=defensive_summary,
            detection_opportunities=detection_opportunities,
            errors=errors,
            exports=exports,
            key_judgments=key_judgments,
            narrative=narrative,
            prioritized_actions=prioritized_actions,
            references=references,
            rollups=rollups,
            source_confidence_statement=source_confidence_statement,
            source_corroboration=source_corroboration,
        )

        artifact_enrichment_report.additional_properties = d
        return artifact_enrichment_report

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
