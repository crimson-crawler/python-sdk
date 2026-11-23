from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichF3Request")


@_attrs_define
class EnrichF3Request:
    """Look up or search fraud techniques from the MITRE Fight Fraud Framework (F3).

    Attributes:
        f3_id (None | str | Unset): F3 ID for direct lookup. Verified present in the current corpus: `F1031`,
            `F1025.003`. F3 borrows real ATT&CK `T####` ids for the techniques it shares with Enterprise ATT&CK (`T1621`),
            so a T-shaped id resolves here too — and, when `techniques` is included, resolves onward into the full ATT&CK
            technique.
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: details,
            knowledgebase, summary, techniques, versions. `versions` attaches the object's KB revision history
            (`revision_history`).
        search (None | str | Unset): Text query to search fraud techniques
    """

    f3_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        f3_id: None | str | Unset
        if isinstance(self.f3_id, Unset):
            f3_id = UNSET
        else:
            f3_id = self.f3_id

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
        if f3_id is not UNSET:
            field_dict["f3_id"] = f3_id
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_f3_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        f3_id = _parse_f3_id(d.pop("f3_id", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        enrich_f3_request = cls(
            f3_id=f3_id,
            include=include,
            search=search,
        )

        enrich_f3_request.additional_properties = d
        return enrich_f3_request

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
