from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.inventory_enrichment_job_response_status import InventoryEnrichmentJobResponseStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.enrichment_job_event import EnrichmentJobEvent
    from ..models.enrichment_job_stage import EnrichmentJobStage
    from ..models.error_detail import ErrorDetail
    from ..models.inventory_enrichment_result import InventoryEnrichmentResult


T = TypeVar("T", bound="InventoryEnrichmentJobResponse")


@_attrs_define
class InventoryEnrichmentJobResponse:
    """Current Inventory Enricher state and, when complete, its findings.

    Attributes:
        created_at (str): UTC ISO 8601 submission timestamp
        enrichment_id (str): Enrichment identifier
        progress (float): Overall completion from 0 to 1
        stages (list[EnrichmentJobStage]): Ordered stage and substage progress
        status (InventoryEnrichmentJobResponseStatus): Current job state
        updated_at (str): UTC ISO 8601 timestamp of the latest progress update
        error (ErrorDetail | None | Unset): Terminal failure detail when status is error
        events (list[EnrichmentJobEvent] | Unset): Rolling structured progress feed
        queue_position (int | None | Unset): Jobs ahead for this API key while queued; 0 means next to run
        result (InventoryEnrichmentResult | None | Unset): Completed per-asset findings and inventory rollup; null until
            status is done
    """

    created_at: str
    enrichment_id: str
    progress: float
    stages: list[EnrichmentJobStage]
    status: InventoryEnrichmentJobResponseStatus
    updated_at: str
    error: ErrorDetail | None | Unset = UNSET
    events: list[EnrichmentJobEvent] | Unset = UNSET
    queue_position: int | None | Unset = UNSET
    result: InventoryEnrichmentResult | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.enrichment_job_event import EnrichmentJobEvent
        from ..models.enrichment_job_stage import EnrichmentJobStage
        from ..models.error_detail import ErrorDetail
        from ..models.inventory_enrichment_result import InventoryEnrichmentResult

        created_at = self.created_at

        enrichment_id = self.enrichment_id

        progress = self.progress

        stages = []
        for stages_item_data in self.stages:
            stages_item = stages_item_data.to_dict()
            stages.append(stages_item)

        status = self.status.value

        updated_at = self.updated_at

        error: dict[str, Any] | None | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        elif isinstance(self.error, ErrorDetail):
            error = self.error.to_dict()
        else:
            error = self.error

        events: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.events, Unset):
            events = []
            for events_item_data in self.events:
                events_item = events_item_data.to_dict()
                events.append(events_item)

        queue_position: int | None | Unset
        if isinstance(self.queue_position, Unset):
            queue_position = UNSET
        else:
            queue_position = self.queue_position

        result: dict[str, Any] | None | Unset
        if isinstance(self.result, Unset):
            result = UNSET
        elif isinstance(self.result, InventoryEnrichmentResult):
            result = self.result.to_dict()
        else:
            result = self.result

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "created_at": created_at,
                "enrichment_id": enrichment_id,
                "progress": progress,
                "stages": stages,
                "status": status,
                "updated_at": updated_at,
            }
        )
        if error is not UNSET:
            field_dict["error"] = error
        if events is not UNSET:
            field_dict["events"] = events
        if queue_position is not UNSET:
            field_dict["queue_position"] = queue_position
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.enrichment_job_event import EnrichmentJobEvent
        from ..models.enrichment_job_stage import EnrichmentJobStage
        from ..models.error_detail import ErrorDetail
        from ..models.inventory_enrichment_result import InventoryEnrichmentResult

        d = dict(src_dict)
        created_at = d.pop("created_at")

        enrichment_id = d.pop("enrichment_id")

        progress = d.pop("progress")

        stages = []
        _stages = d.pop("stages")
        for stages_item_data in _stages:
            stages_item = EnrichmentJobStage.from_dict(stages_item_data)

            stages.append(stages_item)

        status = InventoryEnrichmentJobResponseStatus(d.pop("status"))

        updated_at = d.pop("updated_at")

        def _parse_error(data: object) -> ErrorDetail | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                error_type_0 = ErrorDetail.from_dict(data)

                return error_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ErrorDetail | None | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        _events = d.pop("events", UNSET)
        events: list[EnrichmentJobEvent] | Unset = UNSET
        if _events is not UNSET:
            events = []
            for events_item_data in _events:
                events_item = EnrichmentJobEvent.from_dict(events_item_data)

                events.append(events_item)

        def _parse_queue_position(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        queue_position = _parse_queue_position(d.pop("queue_position", UNSET))

        def _parse_result(data: object) -> InventoryEnrichmentResult | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                result_type_0 = InventoryEnrichmentResult.from_dict(data)

                return result_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(InventoryEnrichmentResult | None | Unset, data)

        result = _parse_result(d.pop("result", UNSET))

        inventory_enrichment_job_response = cls(
            created_at=created_at,
            enrichment_id=enrichment_id,
            progress=progress,
            stages=stages,
            status=status,
            updated_at=updated_at,
            error=error,
            events=events,
            queue_position=queue_position,
            result=result,
        )

        inventory_enrichment_job_response.additional_properties = d
        return inventory_enrichment_job_response

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
