from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.search_cti_request_types_type_0_item import SearchCTIRequestTypesType0Item
from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchCTIRequest")


@_attrs_define
class SearchCTIRequest:
    """Search across multiple threat intelligence knowledge bases simultaneously.

    Attributes:
        query (str): Text search query
        deprecated (bool | None | Unset): Set to false to exclude objects marked deprecated by their source.
        limit (int | Unset): Maximum number of results to return (1-100) Default: 20.
        page (int | Unset): Page number for pagination (1-indexed, max 100) Default: 1.
        revoked (bool | None | Unset): Set to false to exclude objects marked revoked by their source.
        sources (list[str] | Unset): Knowledge bases to search. Options: attack (ATT&CK Enterprise), attack-enterprise,
            attack-ics, attack-mobile, cwe, capec, atlas, disarm, location, sector
        types (list[SearchCTIRequestTypesType0Item] | None | Unset): Filter by object type: attack-pattern, intrusion-
            set, malware, tool, campaign, weakness, course-of-action
    """

    query: str
    deprecated: bool | None | Unset = UNSET
    limit: int | Unset = 20
    page: int | Unset = 1
    revoked: bool | None | Unset = UNSET
    sources: list[str] | Unset = UNSET
    types: list[SearchCTIRequestTypesType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        deprecated: bool | None | Unset
        if isinstance(self.deprecated, Unset):
            deprecated = UNSET
        else:
            deprecated = self.deprecated

        limit = self.limit

        page = self.page

        revoked: bool | None | Unset
        if isinstance(self.revoked, Unset):
            revoked = UNSET
        else:
            revoked = self.revoked

        sources: list[str] | Unset = UNSET
        if not isinstance(self.sources, Unset):
            sources = self.sources

        types: list[str] | None | Unset
        if isinstance(self.types, Unset):
            types = UNSET
        elif isinstance(self.types, list):
            types = []
            for types_type_0_item_data in self.types:
                types_type_0_item = types_type_0_item_data.value
                types.append(types_type_0_item)

        else:
            types = self.types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
            }
        )
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if limit is not UNSET:
            field_dict["limit"] = limit
        if page is not UNSET:
            field_dict["page"] = page
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if sources is not UNSET:
            field_dict["sources"] = sources
        if types is not UNSET:
            field_dict["types"] = types

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query = d.pop("query")

        def _parse_deprecated(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        deprecated = _parse_deprecated(d.pop("deprecated", UNSET))

        limit = d.pop("limit", UNSET)

        page = d.pop("page", UNSET)

        def _parse_revoked(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        revoked = _parse_revoked(d.pop("revoked", UNSET))

        sources = cast(list[str], d.pop("sources", UNSET))

        def _parse_types(data: object) -> list[SearchCTIRequestTypesType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                types_type_0 = []
                _types_type_0 = data
                for types_type_0_item_data in _types_type_0:
                    types_type_0_item = SearchCTIRequestTypesType0Item(types_type_0_item_data)

                    types_type_0.append(types_type_0_item)

                return types_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[SearchCTIRequestTypesType0Item] | None | Unset, data)

        types = _parse_types(d.pop("types", UNSET))

        search_cti_request = cls(
            query=query,
            deprecated=deprecated,
            limit=limit,
            page=page,
            revoked=revoked,
            sources=sources,
            types=types,
        )

        search_cti_request.additional_properties = d
        return search_cti_request

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
