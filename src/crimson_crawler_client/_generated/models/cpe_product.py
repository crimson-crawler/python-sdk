from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CPEProduct")


@_attrs_define
class CPEProduct:
    """Product entry from the CPE dictionary.

    Attributes:
        cpe (str | Unset): CPE 2.3 URI string Default: ''.
        product (str | Unset): Product name Default: ''.
        stix_id (str | Unset): Unique object identifier for cross-referencing Default: ''.
        title (str | Unset): Human-readable product title Default: ''.
        vendor (str | Unset): Vendor name Default: ''.
        version (str | Unset): Product version Default: ''.
    """

    cpe: str | Unset = ""
    product: str | Unset = ""
    stix_id: str | Unset = ""
    title: str | Unset = ""
    vendor: str | Unset = ""
    version: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cpe = self.cpe

        product = self.product

        stix_id = self.stix_id

        title = self.title

        vendor = self.vendor

        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if product is not UNSET:
            field_dict["product"] = product
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if title is not UNSET:
            field_dict["title"] = title
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cpe = d.pop("cpe", UNSET)

        product = d.pop("product", UNSET)

        stix_id = d.pop("stix_id", UNSET)

        title = d.pop("title", UNSET)

        vendor = d.pop("vendor", UNSET)

        version = d.pop("version", UNSET)

        cpe_product = cls(
            cpe=cpe,
            product=product,
            stix_id=stix_id,
            title=title,
            vendor=vendor,
            version=version,
        )

        cpe_product.additional_properties = d
        return cpe_product

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
