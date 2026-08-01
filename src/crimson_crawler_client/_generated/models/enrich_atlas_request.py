from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichATLASRequest")


@_attrs_define
class EnrichATLASRequest:
    """Look up or search adversarial machine learning techniques from the ATLAS knowledge base.

    Attributes:
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, details, detections, groups, knowledgebase, mitigations, navigator, nist_controls, software,
            summary, techniques, tie, web, web_scrape.
        search (None | str | Unset): Text query to search AI/ML attack techniques
        technique_id (None | str | Unset): ATLAS technique ID for direct lookup (e.g. AML.T0043)
    """

    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    technique_id: None | str | Unset = UNSET
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

        technique_id: None | str | Unset
        if isinstance(self.technique_id, Unset):
            technique_id = UNSET
        else:
            technique_id = self.technique_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search
        if technique_id is not UNSET:
            field_dict["technique_id"] = technique_id

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

        def _parse_technique_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        technique_id = _parse_technique_id(d.pop("technique_id", UNSET))

        enrich_atlas_request = cls(
            include=include,
            search=search,
            technique_id=technique_id,
        )

        enrich_atlas_request.additional_properties = d
        return enrich_atlas_request

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
