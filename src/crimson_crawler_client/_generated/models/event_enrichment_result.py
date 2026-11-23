from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.error_detail import ErrorDetail
    from ..models.event_indicator import EventIndicator
    from ..models.event_threat_assessment import EventThreatAssessment
    from ..models.technique_detail import TechniqueDetail


T = TypeVar("T", bound="EventEnrichmentResult")


@_attrs_define
class EventEnrichmentResult:
    """Event Enrichment result — per-indicator enrichment + an aggregate event threat assessment.

    The payload stored on the async job object's ``result`` and returned by the poll endpoint when
    the enrichment is ``done``. It is NOT persisted anywhere else: the engine is stateless by
    decision (#358, closed 2026-09-08 — no consumer, and raw SOC events are too sensitive to hold
    for nobody). The ``event_enrichment`` ``ArtifactKind`` exists (migration 022) but nothing writes
    it. The caller keeps the polled result.

        Attributes:
            threat_assessment (EventThreatAssessment): Aggregate threat verdict across all of an event's indicators.
            errors (list[ErrorDetail] | Unset): Event-level partial-failure details
            event (str | Unset): The original raw event as submitted (retained so a saved result renders input + enrichment)
                Default: ''.
            event_id (None | str | Unset): Caller-supplied event id, echoed (None if not provided)
            extracted_count (int | Unset): Indicators extracted from the event (pre-enrichment-cap total) Default: 0.
            indicators (list[EventIndicator] | Unset): Per-indicator findings (worst-severity / KEV first)
            techniques (list[TechniqueDetail] | Unset): Deduplicated ATT&CK techniques surfaced across every indicator
    """

    threat_assessment: EventThreatAssessment
    errors: list[ErrorDetail] | Unset = UNSET
    event: str | Unset = ""
    event_id: None | str | Unset = UNSET
    extracted_count: int | Unset = 0
    indicators: list[EventIndicator] | Unset = UNSET
    techniques: list[TechniqueDetail] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.event_indicator import EventIndicator  # noqa: PLC0415
        from ..models.event_threat_assessment import EventThreatAssessment  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415

        threat_assessment = self.threat_assessment.to_dict()

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        event = self.event

        event_id: None | str | Unset
        if isinstance(self.event_id, Unset):
            event_id = UNSET
        else:
            event_id = self.event_id

        extracted_count = self.extracted_count

        indicators: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.indicators, Unset):
            indicators = []
            for indicators_item_data in self.indicators:
                indicators_item = indicators_item_data.to_dict()
                indicators.append(indicators_item)

        techniques: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = []
            for techniques_item_data in self.techniques:
                techniques_item = techniques_item_data.to_dict()
                techniques.append(techniques_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "threat_assessment": threat_assessment,
            }
        )
        if errors is not UNSET:
            field_dict["errors"] = errors
        if event is not UNSET:
            field_dict["event"] = event
        if event_id is not UNSET:
            field_dict["event_id"] = event_id
        if extracted_count is not UNSET:
            field_dict["extracted_count"] = extracted_count
        if indicators is not UNSET:
            field_dict["indicators"] = indicators
        if techniques is not UNSET:
            field_dict["techniques"] = techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415
        from ..models.event_indicator import EventIndicator  # noqa: PLC0415
        from ..models.event_threat_assessment import EventThreatAssessment  # noqa: PLC0415
        from ..models.technique_detail import TechniqueDetail  # noqa: PLC0415

        d = dict(src_dict)
        threat_assessment = EventThreatAssessment.from_dict(d.pop("threat_assessment"))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        event = d.pop("event", UNSET)

        def _parse_event_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        event_id = _parse_event_id(d.pop("event_id", UNSET))

        extracted_count = d.pop("extracted_count", UNSET)

        _indicators = d.pop("indicators", UNSET)
        indicators: list[EventIndicator] | Unset = UNSET
        if _indicators is not UNSET:
            indicators = []
            for indicators_item_data in _indicators:
                indicators_item = EventIndicator.from_dict(indicators_item_data)

                indicators.append(indicators_item)

        _techniques = d.pop("techniques", UNSET)
        techniques: list[TechniqueDetail] | Unset = UNSET
        if _techniques is not UNSET:
            techniques = []
            for techniques_item_data in _techniques:
                techniques_item = TechniqueDetail.from_dict(techniques_item_data)

                techniques.append(techniques_item)

        event_enrichment_result = cls(
            threat_assessment=threat_assessment,
            errors=errors,
            event=event,
            event_id=event_id,
            extracted_count=extracted_count,
            indicators=indicators,
            techniques=techniques,
        )

        event_enrichment_result.additional_properties = d
        return event_enrichment_result

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
