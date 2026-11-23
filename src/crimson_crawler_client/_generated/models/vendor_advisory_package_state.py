from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VendorAdvisoryPackageState")


@_attrs_define
class VendorAdvisoryPackageState:
    """One Red Hat package's fix state — including packages Red Hat will not fix.

    Attributes:
        cpe (None | str | Unset): CPE the state applies to
        fix_state (None | str | Unset): Fix state (e.g. 'Not affected', 'Will not fix', 'Fixed')
        package (None | str | Unset): Package name
        product (None | str | Unset): Product name
    """

    cpe: None | str | Unset = UNSET
    fix_state: None | str | Unset = UNSET
    package: None | str | Unset = UNSET
    product: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cpe: None | str | Unset
        if isinstance(self.cpe, Unset):
            cpe = UNSET
        else:
            cpe = self.cpe

        fix_state: None | str | Unset
        if isinstance(self.fix_state, Unset):
            fix_state = UNSET
        else:
            fix_state = self.fix_state

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

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if fix_state is not UNSET:
            field_dict["fix_state"] = fix_state
        if package is not UNSET:
            field_dict["package"] = package
        if product is not UNSET:
            field_dict["product"] = product

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

        def _parse_fix_state(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fix_state = _parse_fix_state(d.pop("fix_state", UNSET))

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

        vendor_advisory_package_state = cls(
            cpe=cpe,
            fix_state=fix_state,
            package=package,
            product=product,
        )

        vendor_advisory_package_state.additional_properties = d
        return vendor_advisory_package_state

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
