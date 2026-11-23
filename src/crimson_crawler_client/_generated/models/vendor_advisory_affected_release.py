from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VendorAdvisoryAffectedRelease")


@_attrs_define
class VendorAdvisoryAffectedRelease:
    """One Red Hat release carrying a fix for the CVE.

    Attributes:
        advisory (None | str | Unset): RHSA/RHBA id
        cpe (None | str | Unset): CPE the release applies to
        impact (None | str | Unset): Impact rating
        package (None | str | Unset): Package name
        product (None | str | Unset): Product name
        released (None | str | Unset): Release date
    """

    advisory: None | str | Unset = UNSET
    cpe: None | str | Unset = UNSET
    impact: None | str | Unset = UNSET
    package: None | str | Unset = UNSET
    product: None | str | Unset = UNSET
    released: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        advisory: None | str | Unset
        if isinstance(self.advisory, Unset):
            advisory = UNSET
        else:
            advisory = self.advisory

        cpe: None | str | Unset
        if isinstance(self.cpe, Unset):
            cpe = UNSET
        else:
            cpe = self.cpe

        impact: None | str | Unset
        if isinstance(self.impact, Unset):
            impact = UNSET
        else:
            impact = self.impact

        package: None | str | Unset
        if isinstance(self.package, Unset):
            package = UNSET
        else:
            package = self.package

        product: None | str | Unset
        if isinstance(self.product, Unset):
            product = UNSET
        else:
            product = self.product

        released: None | str | Unset
        if isinstance(self.released, Unset):
            released = UNSET
        else:
            released = self.released

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if advisory is not UNSET:
            field_dict["advisory"] = advisory
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if impact is not UNSET:
            field_dict["impact"] = impact
        if package is not UNSET:
            field_dict["package"] = package
        if product is not UNSET:
            field_dict["product"] = product
        if released is not UNSET:
            field_dict["released"] = released

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_advisory(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        advisory = _parse_advisory(d.pop("advisory", UNSET))

        def _parse_cpe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cpe = _parse_cpe(d.pop("cpe", UNSET))

        def _parse_impact(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        impact = _parse_impact(d.pop("impact", UNSET))

        def _parse_package(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        package = _parse_package(d.pop("package", UNSET))

        def _parse_product(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product = _parse_product(d.pop("product", UNSET))

        def _parse_released(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        released = _parse_released(d.pop("released", UNSET))

        vendor_advisory_affected_release = cls(
            advisory=advisory,
            cpe=cpe,
            impact=impact,
            package=package,
            product=product,
            released=released,
        )

        vendor_advisory_affected_release.additional_properties = d
        return vendor_advisory_affected_release

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
