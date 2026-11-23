from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichCloakRequest")


@_attrs_define
class EnrichCloakRequest:
    """Look up or search concealment techniques from the CLOAK framework.

    Attributes:
        cloak_id (None | str | Unset): CLOAK ID for direct lookup. Verified present in the current corpus: `TTP-496`,
            `CLOAK`. CLOAK ids are heterogeneous — `TTP-####` tool ids, matrix ids, and lower-case technique slugs — so a
            lookup keyed on an id that does not resolve returns an empty result.
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: details,
            knowledgebase, summary, versions. `versions` attaches the object's KB revision history (`revision_history`).
        search (None | str | Unset): Text query to search concealment techniques
    """

    cloak_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cloak_id: None | str | Unset
        if isinstance(self.cloak_id, Unset):
            cloak_id = UNSET
        else:
            cloak_id = self.cloak_id

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
        if cloak_id is not UNSET:
            field_dict["cloak_id"] = cloak_id
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cloak_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cloak_id = _parse_cloak_id(d.pop("cloak_id", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        enrich_cloak_request = cls(
            cloak_id=cloak_id,
            include=include,
            search=search,
        )

        enrich_cloak_request.additional_properties = d
        return enrich_cloak_request

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
