from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchSectorItem")


@_attrs_define
class BatchSectorItem:
    """Batch item: enrich an industry sector.

    Attributes:
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, details, detections, groups, knowledgebase, locations, mitigations, navigator, software, summary,
            techniques, tie, web, web_scrape.
        search (None | str | Unset): Text query to search sectors by name (e.g. 'healthcare')
        sector_id (None | str | Unset): Sector identifier for direct lookup
        type_ (Literal['sector'] | Unset): Selects sector enrichment for this batch item Default: 'sector'.
    """

    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    sector_id: None | str | Unset = UNSET
    type_: Literal["sector"] | Unset = "sector"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        search: None | str | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        else:
            search = self.search

        sector_id: None | str | Unset
        if isinstance(self.sector_id, Unset):
            sector_id = UNSET
        else:
            sector_id = self.sector_id

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search
        if sector_id is not UNSET:
            field_dict["sector_id"] = sector_id
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        def _parse_sector_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sector_id = _parse_sector_id(d.pop("sector_id", UNSET))

        type_ = cast(Literal["sector"] | Unset, d.pop("type", UNSET))
        if type_ != "sector" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'sector', got '{type_}'")

        batch_sector_item = cls(
            include=include,
            search=search,
            sector_id=sector_id,
            type_=type_,
        )

        batch_sector_item.additional_properties = d
        return batch_sector_item

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
