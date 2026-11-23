from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.listed_on_entry_match import ListedOnEntryMatch
from ..types import UNSET, Unset

T = TypeVar("T", bound="ListedOnEntry")


@_attrs_define
class ListedOnEntry:
    """One list a value appears on — the unified ledger across MISP feeds and Spamhaus.

    Attributes:
        list_ (str): The list within that source (feed name, 'DROP', or 'ASN-DROP')
        match (ListedOnEntryMatch): How the value matched: exact value, CIDR containment, or ASN membership
        source (str): Data source (feed name, or 'Spamhaus DROP' / 'Spamhaus ASN-DROP')
        first_seen (None | str | Unset): Source-published first-seen date, when it publishes one
        last_seen (None | str | Unset): Source-published last-seen date, when it publishes one
        reason (None | str | Unset): Human-readable explanation of the match
    """

    list_: str
    match: ListedOnEntryMatch
    source: str
    first_seen: None | str | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    reason: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        list_ = self.list_

        match = self.match.value

        source = self.source

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "list": list_,
                "match": match,
                "source": source,
            }
        )
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        list_ = d.pop("list")

        match = ListedOnEntryMatch(d.pop("match"))

        source = d.pop("source")

        def _parse_first_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        listed_on_entry = cls(
            list_=list_,
            match=match,
            source=source,
            first_seen=first_seen,
            last_seen=last_seen,
            reason=reason,
        )

        listed_on_entry.additional_properties = d
        return listed_on_entry

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
