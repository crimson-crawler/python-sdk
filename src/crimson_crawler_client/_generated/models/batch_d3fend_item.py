from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchD3FENDItem")


@_attrs_define
class BatchD3FENDItem:
    """Batch item: enrich a D3FEND defensive technique.

    Attributes:
        d3fend_id (None | str | Unset): D3FEND identifier for direct lookup (e.g. D3-AL)
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: details,
            knowledgebase, summary, techniques, web, web_scrape.
        search (None | str | Unset): Text query to search defensive techniques
        type_ (Literal['defend'] | Unset): Selects D3FEND enrichment for this batch item Default: 'defend'.
    """

    d3fend_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    type_: Literal["defend"] | Unset = "defend"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d3fend_id: None | str | Unset
        if isinstance(self.d3fend_id, Unset):
            d3fend_id = UNSET
        else:
            d3fend_id = self.d3fend_id

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        search: None | str | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        else:
            search = self.search

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if d3fend_id is not UNSET:
            field_dict["d3fend_id"] = d3fend_id
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_d3fend_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        d3fend_id = _parse_d3fend_id(d.pop("d3fend_id", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        type_ = cast(Literal["defend"] | Unset, d.pop("type", UNSET))
        if type_ != "defend" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'defend', got '{type_}'")

        batch_d3fend_item = cls(
            d3fend_id=d3fend_id,
            include=include,
            search=search,
            type_=type_,
        )

        batch_d3fend_item.additional_properties = d
        return batch_d3fend_item

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
