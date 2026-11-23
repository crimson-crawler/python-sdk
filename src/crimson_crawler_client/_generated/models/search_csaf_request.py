from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.search_csaf_request_sort import SearchCSAFRequestSort
from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchCSAFRequest")


@_attrs_define
class SearchCSAFRequest:
    """Search the seeded CSAF advisory corpus (vendor/product/sector, including CVE-less advisories).

    Attributes:
        advisory_id (None | str | Unset): Exact tracking id
        cpe (None | str | Unset): CPE substring matched against product-status rows
        cve_id (None | str | Unset): Only advisories whose cve_ids name this CVE
        limit (int | Unset): Page size (1-100) Default: 20.
        page (int | Unset): 1-based page number (max 1000) Default: 1.
        product (None | str | Unset): Product-name substring (case-insensitive)
        publisher (None | str | Unset): Publisher name substring (case-insensitive)
        sector (None | str | Unset): Exact critical-infrastructure sector
        sort (SearchCSAFRequestSort | Unset): Order by current release date Default: SearchCSAFRequestSort.NEWEST.
        tlp (None | str | Unset): Exact TLP label (CLEAR, GREEN, AMBER, RED, WHITE)
    """

    advisory_id: None | str | Unset = UNSET
    cpe: None | str | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    limit: int | Unset = 20
    page: int | Unset = 1
    product: None | str | Unset = UNSET
    publisher: None | str | Unset = UNSET
    sector: None | str | Unset = UNSET
    sort: SearchCSAFRequestSort | Unset = SearchCSAFRequestSort.NEWEST
    tlp: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        advisory_id: None | str | Unset
        if isinstance(self.advisory_id, Unset):
            advisory_id = UNSET
        else:
            advisory_id = self.advisory_id

        cpe: None | str | Unset
        if isinstance(self.cpe, Unset):
            cpe = UNSET
        else:
            cpe = self.cpe

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        limit = self.limit

        page = self.page

        product: None | str | Unset
        if isinstance(self.product, Unset):
            product = UNSET
        else:
            product = self.product

        publisher: None | str | Unset
        if isinstance(self.publisher, Unset):
            publisher = UNSET
        else:
            publisher = self.publisher

        sector: None | str | Unset
        if isinstance(self.sector, Unset):
            sector = UNSET
        else:
            sector = self.sector

        sort: str | Unset = UNSET
        if not isinstance(self.sort, Unset):
            sort = self.sort.value

        tlp: None | str | Unset
        if isinstance(self.tlp, Unset):
            tlp = UNSET
        else:
            tlp = self.tlp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if advisory_id is not UNSET:
            field_dict["advisory_id"] = advisory_id
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if limit is not UNSET:
            field_dict["limit"] = limit
        if page is not UNSET:
            field_dict["page"] = page
        if product is not UNSET:
            field_dict["product"] = product
        if publisher is not UNSET:
            field_dict["publisher"] = publisher
        if sector is not UNSET:
            field_dict["sector"] = sector
        if sort is not UNSET:
            field_dict["sort"] = sort
        if tlp is not UNSET:
            field_dict["tlp"] = tlp

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_advisory_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        advisory_id = _parse_advisory_id(d.pop("advisory_id", UNSET))

        def _parse_cpe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cpe = _parse_cpe(d.pop("cpe", UNSET))

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        limit = d.pop("limit", UNSET)

        page = d.pop("page", UNSET)

        def _parse_product(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product = _parse_product(d.pop("product", UNSET))

        def _parse_publisher(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        publisher = _parse_publisher(d.pop("publisher", UNSET))

        def _parse_sector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sector = _parse_sector(d.pop("sector", UNSET))

        _sort = d.pop("sort", UNSET)
        sort: SearchCSAFRequestSort | Unset
        if isinstance(_sort, Unset):
            sort = UNSET
        else:
            sort = SearchCSAFRequestSort(_sort)

        def _parse_tlp(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tlp = _parse_tlp(d.pop("tlp", UNSET))

        search_csaf_request = cls(
            advisory_id=advisory_id,
            cpe=cpe,
            cve_id=cve_id,
            limit=limit,
            page=page,
            product=product,
            publisher=publisher,
            sector=sector,
            sort=sort,
            tlp=tlp,
        )

        search_csaf_request.additional_properties = d
        return search_csaf_request

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
