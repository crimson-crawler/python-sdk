from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchF3Item")


@_attrs_define
class BatchF3Item:
    """Batch item: enrich an F3 fraud technique.

    Attributes:
        f3_id (None | str | Unset): F3 ID for direct lookup. Verified present in the current corpus: `F1031`,
            `F1025.003`. F3 borrows real ATT&CK `T####` ids for the techniques it shares with Enterprise ATT&CK (`T1621`),
            so a T-shaped id resolves here too — and, when `techniques` is included, resolves onward into the full ATT&CK
            technique.
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: details,
            knowledgebase, summary, techniques, versions. `versions` attaches the object's KB revision history
            (`revision_history`).
        search (None | str | Unset): Text query to search fraud techniques
        type_ (Literal['f3'] | Unset): Selects F3 fraud-framework enrichment for this batch item Default: 'f3'.
    """

    f3_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    type_: Literal["f3"] | Unset = "f3"
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

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if f3_id is not UNSET:
            field_dict["f3_id"] = f3_id
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

        type_ = cast(Literal["f3"] | Unset, d.pop("type", UNSET))
        if type_ != "f3" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'f3', got '{type_}'")

        batch_f3_item = cls(
            f3_id=f3_id,
            include=include,
            search=search,
            type_=type_,
        )

        batch_f3_item.additional_properties = d
        return batch_f3_item

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
