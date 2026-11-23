from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CSAFRemediation")


@_attrs_define
class CSAFRemediation:
    """One remediation entry from a CSAF vulnerability (`mitigation`, `vendor_fix`, `workaround`, …).

    Attributes:
        category (str | Unset): CSAF remediation category Default: ''.
        details (None | str | Unset): Publisher remediation text
        product_ids (list[str] | Unset): CSAF product ids the remediation applies to
        restart_required (None | str | Unset): Restart scope/category, when the publisher states one
        url (None | str | Unset): Publisher remediation link
    """

    category: str | Unset = ""
    details: None | str | Unset = UNSET
    product_ids: list[str] | Unset = UNSET
    restart_required: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        category = self.category

        details: None | str | Unset
        if isinstance(self.details, Unset):
            details = UNSET
        else:
            details = self.details

        product_ids: list[str] | Unset = UNSET
        if not isinstance(self.product_ids, Unset):
            product_ids = self.product_ids

        restart_required: None | str | Unset
        if isinstance(self.restart_required, Unset):
            restart_required = UNSET
        else:
            restart_required = self.restart_required

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if category is not UNSET:
            field_dict["category"] = category
        if details is not UNSET:
            field_dict["details"] = details
        if product_ids is not UNSET:
            field_dict["product_ids"] = product_ids
        if restart_required is not UNSET:
            field_dict["restart_required"] = restart_required
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        category = d.pop("category", UNSET)

        def _parse_details(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        details = _parse_details(d.pop("details", UNSET))

        product_ids = cast(list[str], d.pop("product_ids", UNSET))

        def _parse_restart_required(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        restart_required = _parse_restart_required(d.pop("restart_required", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        csaf_remediation = cls(
            category=category,
            details=details,
            product_ids=product_ids,
            restart_required=restart_required,
            url=url,
        )

        csaf_remediation.additional_properties = d
        return csaf_remediation

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
