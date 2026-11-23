from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CPEVendor")


@_attrs_define
class CPEVendor:
    """One CPE-dictionary vendor with its catalogue size.

    Attributes:
        products_count (int | Unset): Products in the CPE dictionary for this vendor Default: 0.
        softwares_count (int | Unset): Software entries in the CPE dictionary for this vendor Default: 0.
        vendor (str | Unset): Vendor slug (pass this back as `vendor`) Default: ''.
    """

    products_count: int | Unset = 0
    softwares_count: int | Unset = 0
    vendor: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        products_count = self.products_count

        softwares_count = self.softwares_count

        vendor = self.vendor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if products_count is not UNSET:
            field_dict["products_count"] = products_count
        if softwares_count is not UNSET:
            field_dict["softwares_count"] = softwares_count
        if vendor is not UNSET:
            field_dict["vendor"] = vendor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        products_count = d.pop("products_count", UNSET)

        softwares_count = d.pop("softwares_count", UNSET)

        vendor = d.pop("vendor", UNSET)

        cpe_vendor = cls(
            products_count=products_count,
            softwares_count=softwares_count,
            vendor=vendor,
        )

        cpe_vendor.additional_properties = d
        return cpe_vendor

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
