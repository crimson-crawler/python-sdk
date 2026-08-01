from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.search_knowledgebase_request_collections_item import SearchKnowledgebaseRequestCollectionsItem
from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchKnowledgebaseRequest")


@_attrs_define
class SearchKnowledgebaseRequest:
    """Search the knowledge base using natural language queries.

    Attributes:
        query (str): Natural language search query
        alpha (float | Unset): Search relevance tuning parameter (0.0 to 1.0). Default 0.7 Default: 0.7.
        collections (list[SearchKnowledgebaseRequestCollectionsItem] | Unset): Knowledge base collections to search.
            Defaults to red_team — the only collection seeded with substantial content (adversarial tradecraft playbooks).
            Options: main (general KB / test fixtures), large (extended corpus), user (user-uploaded content), red_team
            (adversarial tradecraft playbooks)
        limit (int | Unset): Maximum number of results to return (1-100) Default: 10.
    """

    query: str
    alpha: float | Unset = 0.7
    collections: list[SearchKnowledgebaseRequestCollectionsItem] | Unset = UNSET
    limit: int | Unset = 10
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        alpha = self.alpha

        collections: list[str] | Unset = UNSET
        if not isinstance(self.collections, Unset):
            collections = []
            for collections_item_data in self.collections:
                collections_item = collections_item_data.value
                collections.append(collections_item)

        limit = self.limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
            }
        )
        if alpha is not UNSET:
            field_dict["alpha"] = alpha
        if collections is not UNSET:
            field_dict["collections"] = collections
        if limit is not UNSET:
            field_dict["limit"] = limit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        query = d.pop("query")

        alpha = d.pop("alpha", UNSET)

        _collections = d.pop("collections", UNSET)
        collections: list[SearchKnowledgebaseRequestCollectionsItem] | Unset = UNSET
        if _collections is not UNSET:
            collections = []
            for collections_item_data in _collections:
                collections_item = SearchKnowledgebaseRequestCollectionsItem(collections_item_data)

                collections.append(collections_item)

        limit = d.pop("limit", UNSET)

        search_knowledgebase_request = cls(
            query=query,
            alpha=alpha,
            collections=collections,
            limit=limit,
        )

        search_knowledgebase_request.additional_properties = d
        return search_knowledgebase_request

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
