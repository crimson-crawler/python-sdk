from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AffectedConfiguration")


@_attrs_define
class AffectedConfiguration:
    """One affected product + version range from the CVE's NVD configurations (CPE match criteria), deduplicated.

    Attributes:
        product (str | Unset): CPE product Default: ''.
        vendor (str | Unset): CPE vendor Default: ''.
        version (None | str | Unset): Exact affected version, when the criterion names one
        version_end_excluding (None | str | Unset): Range end, exclusive (the first fixed version)
        version_end_including (None | str | Unset): Range end, inclusive
        version_start_excluding (None | str | Unset): Range start, exclusive
        version_start_including (None | str | Unset): Range start, inclusive
    """

    product: str | Unset = ""
    vendor: str | Unset = ""
    version: None | str | Unset = UNSET
    version_end_excluding: None | str | Unset = UNSET
    version_end_including: None | str | Unset = UNSET
    version_start_excluding: None | str | Unset = UNSET
    version_start_including: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        product = self.product

        vendor = self.vendor

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        version_end_excluding: None | str | Unset
        if isinstance(self.version_end_excluding, Unset):
            version_end_excluding = UNSET
        else:
            version_end_excluding = self.version_end_excluding

        version_end_including: None | str | Unset
        if isinstance(self.version_end_including, Unset):
            version_end_including = UNSET
        else:
            version_end_including = self.version_end_including

        version_start_excluding: None | str | Unset
        if isinstance(self.version_start_excluding, Unset):
            version_start_excluding = UNSET
        else:
            version_start_excluding = self.version_start_excluding

        version_start_including: None | str | Unset
        if isinstance(self.version_start_including, Unset):
            version_start_including = UNSET
        else:
            version_start_including = self.version_start_including

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if product is not UNSET:
            field_dict["product"] = product
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version
        if version_end_excluding is not UNSET:
            field_dict["version_end_excluding"] = version_end_excluding
        if version_end_including is not UNSET:
            field_dict["version_end_including"] = version_end_including
        if version_start_excluding is not UNSET:
            field_dict["version_start_excluding"] = version_start_excluding
        if version_start_including is not UNSET:
            field_dict["version_start_including"] = version_start_including

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        product = d.pop("product", UNSET)

        vendor = d.pop("vendor", UNSET)

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        def _parse_version_end_excluding(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_end_excluding = _parse_version_end_excluding(d.pop("version_end_excluding", UNSET))

        def _parse_version_end_including(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_end_including = _parse_version_end_including(d.pop("version_end_including", UNSET))

        def _parse_version_start_excluding(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_start_excluding = _parse_version_start_excluding(d.pop("version_start_excluding", UNSET))

        def _parse_version_start_including(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_start_including = _parse_version_start_including(d.pop("version_start_including", UNSET))

        affected_configuration = cls(
            product=product,
            vendor=vendor,
            version=version,
            version_end_excluding=version_end_excluding,
            version_end_including=version_end_including,
            version_start_excluding=version_start_excluding,
            version_start_including=version_start_including,
        )

        affected_configuration.additional_properties = d
        return affected_configuration

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
