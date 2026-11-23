from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VendorAdvisoryRemediation")


@_attrs_define
class VendorAdvisoryRemediation:
    """One MSRC CVRF remediation. `kb` and `label` are mutually exclusive by construction.

    Attributes:
        fixed_build (None | str | Unset): Build the fix lands in
        kb (None | str | Unset): Knowledge-base number, when the description is one
        label (None | str | Unset): Literal label, when the description is not a KB number
        products (list[str] | Unset): Product names this remediation applies to
        restart_required (None | str | Unset): Whether a restart is required
        sub_type (None | str | Unset): Remediation subtype
        supercedence (None | str | Unset): Update this one supersedes
        url (None | str | Unset): Remediation URL
    """

    fixed_build: None | str | Unset = UNSET
    kb: None | str | Unset = UNSET
    label: None | str | Unset = UNSET
    products: list[str] | Unset = UNSET
    restart_required: None | str | Unset = UNSET
    sub_type: None | str | Unset = UNSET
    supercedence: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fixed_build: None | str | Unset
        if isinstance(self.fixed_build, Unset):
            fixed_build = UNSET
        else:
            fixed_build = self.fixed_build

        kb: None | str | Unset
        if isinstance(self.kb, Unset):
            kb = UNSET
        else:
            kb = self.kb

        label: None | str | Unset
        if isinstance(self.label, Unset):
            label = UNSET
        else:
            label = self.label

        products: list[str] | Unset = UNSET
        if not isinstance(self.products, Unset):
            products = self.products

        restart_required: None | str | Unset
        if isinstance(self.restart_required, Unset):
            restart_required = UNSET
        else:
            restart_required = self.restart_required

        sub_type: None | str | Unset
        if isinstance(self.sub_type, Unset):
            sub_type = UNSET
        else:
            sub_type = self.sub_type

        supercedence: None | str | Unset
        if isinstance(self.supercedence, Unset):
            supercedence = UNSET
        else:
            supercedence = self.supercedence

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if fixed_build is not UNSET:
            field_dict["fixed_build"] = fixed_build
        if kb is not UNSET:
            field_dict["kb"] = kb
        if label is not UNSET:
            field_dict["label"] = label
        if products is not UNSET:
            field_dict["products"] = products
        if restart_required is not UNSET:
            field_dict["restart_required"] = restart_required
        if sub_type is not UNSET:
            field_dict["sub_type"] = sub_type
        if supercedence is not UNSET:
            field_dict["supercedence"] = supercedence
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_fixed_build(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fixed_build = _parse_fixed_build(d.pop("fixed_build", UNSET))

        def _parse_kb(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kb = _parse_kb(d.pop("kb", UNSET))

        def _parse_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        label = _parse_label(d.pop("label", UNSET))

        products = cast(list[str], d.pop("products", UNSET))

        def _parse_restart_required(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        restart_required = _parse_restart_required(d.pop("restart_required", UNSET))

        def _parse_sub_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sub_type = _parse_sub_type(d.pop("sub_type", UNSET))

        def _parse_supercedence(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        supercedence = _parse_supercedence(d.pop("supercedence", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        vendor_advisory_remediation = cls(
            fixed_build=fixed_build,
            kb=kb,
            label=label,
            products=products,
            restart_required=restart_required,
            sub_type=sub_type,
            supercedence=supercedence,
            url=url,
        )

        vendor_advisory_remediation.additional_properties = d
        return vendor_advisory_remediation

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
