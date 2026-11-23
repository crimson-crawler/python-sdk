from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_event_attribute_stats_by_category import MISPEventAttributeStatsByCategory


T = TypeVar("T", bound="MISPEventAttributeStats")


@_attrs_define
class MISPEventAttributeStats:
    """What an event's attributes are MADE of, beyond their count.

    Attributes:
        by_category (MISPEventAttributeStatsByCategory | Unset): Attribute count per MISP category name
        total (int | Unset): Total attributes in the event Default: 0.
    """

    by_category: MISPEventAttributeStatsByCategory | Unset = UNSET
    total: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_event_attribute_stats_by_category import MISPEventAttributeStatsByCategory  # noqa: PLC0415

        by_category: dict[str, Any] | Unset = UNSET
        if not isinstance(self.by_category, Unset):
            by_category = self.by_category.to_dict()

        total = self.total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if by_category is not UNSET:
            field_dict["by_category"] = by_category
        if total is not UNSET:
            field_dict["total"] = total

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_event_attribute_stats_by_category import MISPEventAttributeStatsByCategory  # noqa: PLC0415

        d = dict(src_dict)
        _by_category = d.pop("by_category", UNSET)
        by_category: MISPEventAttributeStatsByCategory | Unset
        if isinstance(_by_category, Unset):
            by_category = UNSET
        else:
            by_category = MISPEventAttributeStatsByCategory.from_dict(_by_category)

        total = d.pop("total", UNSET)

        misp_event_attribute_stats = cls(
            by_category=by_category,
            total=total,
        )

        misp_event_attribute_stats.additional_properties = d
        return misp_event_attribute_stats

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
