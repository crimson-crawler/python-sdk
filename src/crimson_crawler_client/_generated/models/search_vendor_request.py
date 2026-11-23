from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchVendorRequest")


@_attrs_define
class SearchVendorRequest:
    """List products from a vendor, or enumerate the vendor directory.

    Two modes on one surface: pass `vendor` for that vendor's product catalogue; omit it (optionally
    with `q`) to enumerate the CPE vendor directory — 22,364 vendors with their product counts, the
    discovery half that had no consumer path (`search_cpe_vendors` was written and never called).

        Attributes:
            limit (int | Unset): Maximum number of products to return (1-100) in vendor mode; directory-mode rows are capped
                at this too. A product contributes one row per CPE entry it has, so `products` can be longer than this. Default:
                50.
            q (None | str | Unset): Wildcard filter on vendor name — directory mode only
            vendor (None | str | Unset): Vendor name (e.g. 'apache'). Omit to enumerate the vendor directory instead.
    """

    limit: int | Unset = 50
    q: None | str | Unset = UNSET
    vendor: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        limit = self.limit

        q: None | str | Unset
        if isinstance(self.q, Unset):
            q = UNSET
        else:
            q = self.q

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if limit is not UNSET:
            field_dict["limit"] = limit
        if q is not UNSET:
            field_dict["q"] = q
        if vendor is not UNSET:
            field_dict["vendor"] = vendor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        limit = d.pop("limit", UNSET)

        def _parse_q(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        q = _parse_q(d.pop("q", UNSET))

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        search_vendor_request = cls(
            limit=limit,
            q=q,
            vendor=vendor,
        )

        search_vendor_request.additional_properties = d
        return search_vendor_request

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
