from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KevOTContext")


@_attrs_define
class KevOTContext:
    """Whether a KEV entry's vendor is an operational-technology vendor.

    Attributes:
        is_ot (bool | Unset): KEV vendorProject matches the curated OT vendor table Default: False.
        ot_vendor (None | str | Unset): The curated vendor name that matched
        source (str | Unset): Stable source label Default: 'kev_vendor_map'.
    """

    is_ot: bool | Unset = False
    ot_vendor: None | str | Unset = UNSET
    source: str | Unset = "kev_vendor_map"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        is_ot = self.is_ot

        ot_vendor: None | str | Unset
        if isinstance(self.ot_vendor, Unset):
            ot_vendor = UNSET
        else:
            ot_vendor = self.ot_vendor

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if is_ot is not UNSET:
            field_dict["is_ot"] = is_ot
        if ot_vendor is not UNSET:
            field_dict["ot_vendor"] = ot_vendor
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        is_ot = d.pop("is_ot", UNSET)

        def _parse_ot_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ot_vendor = _parse_ot_vendor(d.pop("ot_vendor", UNSET))

        source = d.pop("source", UNSET)

        kev_ot_context = cls(
            is_ot=is_ot,
            ot_vendor=ot_vendor,
            source=source,
        )

        kev_ot_context.additional_properties = d
        return kev_ot_context

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
