from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MISPFeedHit")


@_attrs_define
class MISPFeedHit:
    """Supplemental threat-feed match for an indicator value.

    Attributes:
        id (str | Unset): MISP feed ID Default: ''.
        name (str | Unset): Feed name (e.g. 'URLhaus', 'Threatfox') Default: ''.
        provider (str | Unset): Feed provider (e.g. 'abuse.ch') Default: ''.
        source_format (str | Unset): Feed source format (misp, csv, freetext, or 1) Default: ''.
        url (str | Unset): Feed source URL Default: ''.
    """

    id: str | Unset = ""
    name: str | Unset = ""
    provider: str | Unset = ""
    source_format: str | Unset = ""
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        provider = self.provider

        source_format = self.source_format

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if provider is not UNSET:
            field_dict["provider"] = provider
        if source_format is not UNSET:
            field_dict["source_format"] = source_format
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        provider = d.pop("provider", UNSET)

        source_format = d.pop("source_format", UNSET)

        url = d.pop("url", UNSET)

        misp_feed_hit = cls(
            id=id,
            name=name,
            provider=provider,
            source_format=source_format,
            url=url,
        )

        misp_feed_hit.additional_properties = d
        return misp_feed_hit

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
