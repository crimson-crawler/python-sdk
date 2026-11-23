from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AffectedChipset")


@_attrs_define
class AffectedChipset:
    """One chipset/SoC row presented from the CVE's Vulmatch `software` objects.

    A presentation transform, not a new source: the software read behind
    `affected_products` already carries these rows. A Qualcomm-family vendor
    (qualcomm/qca/snapdragon) qualifies, and a `_firmware` suffix is stripped from
    the product name so the row names the chipset rather than a firmware build.

        Attributes:
            cpe (None | str | Unset): The full CPE string
            product (None | str | Unset): Chipset/SoC product name, `_firmware` suffix stripped
            source (str | Unset): Stable source label Default: 'vulmatch'.
            source_url (str | Unset): Upstream source URL, when one applies Default: ''.
            vendor (None | str | Unset): CPE vendor (qualcomm, qca, snapdragon)
            version (None | str | Unset): Version the CPE names
    """

    cpe: None | str | Unset = UNSET
    product: None | str | Unset = UNSET
    source: str | Unset = "vulmatch"
    source_url: str | Unset = ""
    vendor: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cpe: None | str | Unset
        if isinstance(self.cpe, Unset):
            cpe = UNSET
        else:
            cpe = self.cpe

        product: None | str | Unset
        if isinstance(self.product, Unset):
            product = UNSET
        else:
            product = self.product

        source = self.source

        source_url = self.source_url

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if product is not UNSET:
            field_dict["product"] = product
        if source is not UNSET:
            field_dict["source"] = source
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cpe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cpe = _parse_cpe(d.pop("cpe", UNSET))

        def _parse_product(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product = _parse_product(d.pop("product", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        affected_chipset = cls(
            cpe=cpe,
            product=product,
            source=source,
            source_url=source_url,
            vendor=vendor,
            version=version,
        )

        affected_chipset.additional_properties = d
        return affected_chipset

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
