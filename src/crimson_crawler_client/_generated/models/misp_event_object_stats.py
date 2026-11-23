from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_event_object_stats_by_name import MISPEventObjectStatsByName


T = TypeVar("T", bound="MISPEventObjectStats")


@_attrs_define
class MISPEventObjectStats:
    """What an event's composite objects are MADE of.

    Attributes:
        by_name (MISPEventObjectStatsByName | Unset): Object count per object-template name
        total (int | Unset): Total composite objects in the event Default: 0.
    """

    by_name: MISPEventObjectStatsByName | Unset = UNSET
    total: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_event_object_stats_by_name import MISPEventObjectStatsByName  # noqa: PLC0415

        by_name: dict[str, Any] | Unset = UNSET
        if not isinstance(self.by_name, Unset):
            by_name = self.by_name.to_dict()

        total = self.total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if by_name is not UNSET:
            field_dict["by_name"] = by_name
        if total is not UNSET:
            field_dict["total"] = total

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_event_object_stats_by_name import MISPEventObjectStatsByName  # noqa: PLC0415

        d = dict(src_dict)
        _by_name = d.pop("by_name", UNSET)
        by_name: MISPEventObjectStatsByName | Unset
        if isinstance(_by_name, Unset):
            by_name = UNSET
        else:
            by_name = MISPEventObjectStatsByName.from_dict(_by_name)

        total = d.pop("total", UNSET)

        misp_event_object_stats = cls(
            by_name=by_name,
            total=total,
        )

        misp_event_object_stats.additional_properties = d
        return misp_event_object_stats

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
