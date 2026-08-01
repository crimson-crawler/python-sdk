from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.enrichment_job_stage_status import EnrichmentJobStageStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.enrichment_job_substage import EnrichmentJobSubstage


T = TypeVar("T", bound="EnrichmentJobStage")


@_attrs_define
class EnrichmentJobStage:
    """Progress for one stage of an asynchronous enrichment.

    Attributes:
        key (str): Stable stage identifier
        label (str): Human-readable stage label
        status (EnrichmentJobStageStatus): Current stage state
        detail (None | str | Unset): Latest progress or failure detail
        progress (float | None | Unset): Stage completion from 0 to 1
        substages (list[EnrichmentJobSubstage] | Unset): Ordered progress steps within this stage
    """

    key: str
    label: str
    status: EnrichmentJobStageStatus
    detail: None | str | Unset = UNSET
    progress: float | None | Unset = UNSET
    substages: list[EnrichmentJobSubstage] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.enrichment_job_substage import EnrichmentJobSubstage

        key = self.key

        label = self.label

        status = self.status.value

        detail: None | str | Unset
        if isinstance(self.detail, Unset):
            detail = UNSET
        else:
            detail = self.detail

        progress: float | None | Unset
        if isinstance(self.progress, Unset):
            progress = UNSET
        else:
            progress = self.progress

        substages: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.substages, Unset):
            substages = []
            for substages_item_data in self.substages:
                substages_item = substages_item_data.to_dict()
                substages.append(substages_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "key": key,
                "label": label,
                "status": status,
            }
        )
        if detail is not UNSET:
            field_dict["detail"] = detail
        if progress is not UNSET:
            field_dict["progress"] = progress
        if substages is not UNSET:
            field_dict["substages"] = substages

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.enrichment_job_substage import EnrichmentJobSubstage

        d = dict(src_dict)
        key = d.pop("key")

        label = d.pop("label")

        status = EnrichmentJobStageStatus(d.pop("status"))

        def _parse_detail(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detail = _parse_detail(d.pop("detail", UNSET))

        def _parse_progress(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        progress = _parse_progress(d.pop("progress", UNSET))

        _substages = d.pop("substages", UNSET)
        substages: list[EnrichmentJobSubstage] | Unset = UNSET
        if _substages is not UNSET:
            substages = []
            for substages_item_data in _substages:
                substages_item = EnrichmentJobSubstage.from_dict(substages_item_data)

                substages.append(substages_item)

        enrichment_job_stage = cls(
            key=key,
            label=label,
            status=status,
            detail=detail,
            progress=progress,
            substages=substages,
        )

        enrichment_job_stage.additional_properties = d
        return enrichment_job_stage

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
