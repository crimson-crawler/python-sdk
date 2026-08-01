from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchCAPECItem")


@_attrs_define
class BatchCAPECItem:
    """Batch item: enrich a CAPEC attack pattern.

    Attributes:
        capec_id (None | str | Unset): CAPEC identifier for direct lookup (e.g. CAPEC-66)
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, details, detections, groups, knowledgebase, mitigations, navigator, nist_controls, software,
            summary, techniques, tie, web, web_scrape.
        search (None | str | Unset): Text query to search attack patterns by name or description
        type_ (Literal['capec'] | Unset): Selects CAPEC enrichment for this batch item Default: 'capec'.
    """

    capec_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    type_: Literal["capec"] | Unset = "capec"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        capec_id: None | str | Unset
        if isinstance(self.capec_id, Unset):
            capec_id = UNSET
        else:
            capec_id = self.capec_id

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
        if capec_id is not UNSET:
            field_dict["capec_id"] = capec_id
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

        def _parse_capec_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        capec_id = _parse_capec_id(d.pop("capec_id", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        type_ = cast(Literal["capec"] | Unset, d.pop("type", UNSET))
        if type_ != "capec" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'capec', got '{type_}'")

        batch_capec_item = cls(
            capec_id=capec_id,
            include=include,
            search=search,
            type_=type_,
        )

        batch_capec_item.additional_properties = d
        return batch_capec_item

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
