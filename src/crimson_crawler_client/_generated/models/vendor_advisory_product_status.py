from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VendorAdvisoryProductStatus")


@_attrs_define
class VendorAdvisoryProductStatus:
    """One MSRC product-status group (`Known Affected`, `Known Not Affected`, …).

    Attributes:
        products (list[str] | Unset): Product names in that status
        status_type (None | str | Unset): Status as MSRC names it
    """

    products: list[str] | Unset = UNSET
    status_type: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        products: list[str] | Unset = UNSET
        if not isinstance(self.products, Unset):
            products = self.products

        status_type: None | str | Unset
        if isinstance(self.status_type, Unset):
            status_type = UNSET
        else:
            status_type = self.status_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if products is not UNSET:
            field_dict["products"] = products
        if status_type is not UNSET:
            field_dict["status_type"] = status_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        products = cast(list[str], d.pop("products", UNSET))

        def _parse_status_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status_type = _parse_status_type(d.pop("status_type", UNSET))

        vendor_advisory_product_status = cls(
            products=products,
            status_type=status_type,
        )

        vendor_advisory_product_status.additional_properties = d
        return vendor_advisory_product_status

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
