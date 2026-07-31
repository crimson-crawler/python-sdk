from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichCAPECRequest")


@_attrs_define
class EnrichCAPECRequest:
    """Look up or search attack patterns and resolve linked adversary techniques.

    Attributes:
        capec_id (None | str | Unset): CAPEC identifier for direct lookup (e.g. CAPEC-66)
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, details, detections, groups, knowledgebase, mitigations, navigator, nist_controls, software,
            summary, techniques, tie, web, web_scrape.
        search (None | str | Unset): Text query to search attack patterns by name or description
    """

    capec_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
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

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if capec_id is not UNSET:
            field_dict["capec_id"] = capec_id
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search

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

        enrich_capec_request = cls(
            capec_id=capec_id,
            include=include,
            search=search,
        )

        enrich_capec_request.additional_properties = d
        return enrich_capec_request

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
