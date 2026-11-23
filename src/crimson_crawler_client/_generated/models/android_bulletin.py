from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AndroidBulletin")


@_attrs_define
class AndroidBulletin:
    """Android Security Bulletin associated with a CVE.

    Attributes:
        asb_id (str): Android Security Bulletin id (ASB-A-…)
        source_url (str): The OSV API record the alias came from
        url (str): The bulletin's OSV record URL
        aliases (list[None | str] | Unset): Every alias the OSV record carries; malformed entries are null
        attribution (str | Unset): Android bulletin attribution Default: 'Android Open Source Project; CC-BY-4.0
            https://creativecommons.org/licenses/by/4.0/; fields selected for presentation'.
        component (None | str | Unset): Android component the bulletin names, when it does
        licence (str | Unset): Android Security Bulletin licence Default: 'CC-BY-4.0'.
        published (None | str | Unset): Publication timestamp from the OSV record
        retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
        severity (None | str | Unset): Severity the OSV record publishes
        source (str | Unset): Stable source label Default: 'osv'.
    """

    asb_id: str
    source_url: str
    url: str
    aliases: list[None | str] | Unset = UNSET
    attribution: str | Unset = (
        "Android Open Source Project; CC-BY-4.0 https://creativecommons.org/licenses/by/4.0/; fields selected for presentation"
    )
    component: None | str | Unset = UNSET
    licence: str | Unset = "CC-BY-4.0"
    published: None | str | Unset = UNSET
    retrieved_at: str | Unset = ""
    severity: None | str | Unset = UNSET
    source: str | Unset = "osv"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asb_id = self.asb_id

        source_url = self.source_url

        url = self.url

        aliases: list[None | str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = []
            for aliases_item_data in self.aliases:
                aliases_item: None | str
                aliases_item = aliases_item_data
                aliases.append(aliases_item)

        attribution = self.attribution

        component: None | str | Unset
        if isinstance(self.component, Unset):
            component = UNSET
        else:
            component = self.component

        licence = self.licence

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        retrieved_at = self.retrieved_at

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asb_id": asb_id,
                "source_url": source_url,
                "url": url,
            }
        )
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if component is not UNSET:
            field_dict["component"] = component
        if licence is not UNSET:
            field_dict["licence"] = licence
        if published is not UNSET:
            field_dict["published"] = published
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if severity is not UNSET:
            field_dict["severity"] = severity
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asb_id = d.pop("asb_id")

        source_url = d.pop("source_url")

        url = d.pop("url")

        _aliases = d.pop("aliases", UNSET)
        aliases: list[None | str] | Unset = UNSET
        if _aliases is not UNSET:
            aliases = []
            for aliases_item_data in _aliases:

                def _parse_aliases_item(data: object) -> None | str:
                    if data is None:
                        return data
                    return cast(None | str, data)

                aliases_item = _parse_aliases_item(aliases_item_data)

                aliases.append(aliases_item)

        attribution = d.pop("attribution", UNSET)

        def _parse_component(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        component = _parse_component(d.pop("component", UNSET))

        licence = d.pop("licence", UNSET)

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        retrieved_at = d.pop("retrieved_at", UNSET)

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        source = d.pop("source", UNSET)

        android_bulletin = cls(
            asb_id=asb_id,
            source_url=source_url,
            url=url,
            aliases=aliases,
            attribution=attribution,
            component=component,
            licence=licence,
            published=published,
            retrieved_at=retrieved_at,
            severity=severity,
            source=source,
        )

        android_bulletin.additional_properties = d
        return android_bulletin

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
