from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.weakness_rank_list import WeaknessRankList
from ..types import UNSET, Unset

T = TypeVar("T", bound="WeaknessRank")


@_attrs_define
class WeaknessRank:
    """One ranked-list position a CVE's weakness occupies (CWE Top 25 or an OWASP Top 10).

    Matching is CWE → row, never category-name text: a CWE that an OWASP edition maps
    to a category produces that category's row, and one CWE can sit in several
    categories (a different question from its single CWE Top 25 rank).

        Attributes:
            list_ (WeaknessRankList): Which ranked list produced this row
            rank (int): The row's position in that edition's ranking
            source_version (str): Dataset edition identifier, e.g. cwe_top25_2025
            url (str): The edition's own page for this rank/category
            year (int): Edition year of the ranked list
            category (None | str | Unset): OWASP category name (OWASP rows only)
            cwe_id (None | str | Unset): The ranked CWE (CWE Top 25 rows only)
            source (str | Unset): Stable source label Default: 'weakness_ranks'.
    """

    list_: WeaknessRankList
    rank: int
    source_version: str
    url: str
    year: int
    category: None | str | Unset = UNSET
    cwe_id: None | str | Unset = UNSET
    source: str | Unset = "weakness_ranks"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        list_ = self.list_.value

        rank = self.rank

        source_version = self.source_version

        url = self.url

        year = self.year

        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        else:
            category = self.category

        cwe_id: None | str | Unset
        if isinstance(self.cwe_id, Unset):
            cwe_id = UNSET
        else:
            cwe_id = self.cwe_id

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "list": list_,
                "rank": rank,
                "source_version": source_version,
                "url": url,
                "year": year,
            }
        )
        if category is not UNSET:
            field_dict["category"] = category
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        list_ = WeaknessRankList(d.pop("list"))

        rank = d.pop("rank")

        source_version = d.pop("source_version")

        url = d.pop("url")

        year = d.pop("year")

        def _parse_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        def _parse_cwe_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cwe_id = _parse_cwe_id(d.pop("cwe_id", UNSET))

        source = d.pop("source", UNSET)

        weakness_rank = cls(
            list_=list_,
            rank=rank,
            source_version=source_version,
            url=url,
            year=year,
            category=category,
            cwe_id=cwe_id,
            source=source,
        )

        weakness_rank.additional_properties = d
        return weakness_rank

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
