from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.enrichment_job_substage_status import EnrichmentJobSubstageStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichmentJobSubstage")


@_attrs_define
class EnrichmentJobSubstage:
    """Progress for one step within an asynchronous enrichment stage.

    Attributes:
        key (str): Stable substage identifier
        label (str): Human-readable substage label
        status (EnrichmentJobSubstageStatus): Current substage state
        detail (None | str | Unset): Latest progress or failure detail
        progress (float | None | Unset): Substage completion from 0 to 1
    """

    key: str
    label: str
    status: EnrichmentJobSubstageStatus
    detail: None | str | Unset = UNSET
    progress: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
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

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        key = d.pop("key")

        label = d.pop("label")

        status = EnrichmentJobSubstageStatus(d.pop("status"))

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

        enrichment_job_substage = cls(
            key=key,
            label=label,
            status=status,
            detail=detail,
            progress=progress,
        )

        enrichment_job_substage.additional_properties = d
        return enrichment_job_substage

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
