from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VINCEAdvisory")


@_attrs_define
class VINCEAdvisory:
    """A CERT/CC Vulnerability Note for a CVE (VINCE).

    Attributes:
        source_url (str): The note API URL
        title (str): Note title
        url (str): Note URL
        vuid (str): CERT/CC Vulnerability Note id (VU#…)
        attribution (str | Unset): Source attribution Default: ''.
        csaf_url (None | str | Unset): The note's CSAF document URL
        licence (str | Unset): Source licence status Default: 'unknown'.
        published (None | str | Unset): Publication date
        retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
        source (str | Unset): Stable source label Default: 'cert_vince'.
        updated (None | str | Unset): Last revision date (`dateupdated`)
    """

    source_url: str
    title: str
    url: str
    vuid: str
    attribution: str | Unset = ""
    csaf_url: None | str | Unset = UNSET
    licence: str | Unset = "unknown"
    published: None | str | Unset = UNSET
    retrieved_at: str | Unset = ""
    source: str | Unset = "cert_vince"
    updated: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_url = self.source_url

        title = self.title

        url = self.url

        vuid = self.vuid

        attribution = self.attribution

        csaf_url: None | str | Unset
        if isinstance(self.csaf_url, Unset):
            csaf_url = UNSET
        else:
            csaf_url = self.csaf_url

        licence = self.licence

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        retrieved_at = self.retrieved_at

        source = self.source

        updated: None | str | Unset
        if isinstance(self.updated, Unset):
            updated = UNSET
        else:
            updated = self.updated

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_url": source_url,
                "title": title,
                "url": url,
                "vuid": vuid,
            }
        )
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if csaf_url is not UNSET:
            field_dict["csaf_url"] = csaf_url
        if licence is not UNSET:
            field_dict["licence"] = licence
        if published is not UNSET:
            field_dict["published"] = published
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if source is not UNSET:
            field_dict["source"] = source
        if updated is not UNSET:
            field_dict["updated"] = updated

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_url = d.pop("source_url")

        title = d.pop("title")

        url = d.pop("url")

        vuid = d.pop("vuid")

        attribution = d.pop("attribution", UNSET)

        def _parse_csaf_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        csaf_url = _parse_csaf_url(d.pop("csaf_url", UNSET))

        licence = d.pop("licence", UNSET)

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        retrieved_at = d.pop("retrieved_at", UNSET)

        source = d.pop("source", UNSET)

        def _parse_updated(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        updated = _parse_updated(d.pop("updated", UNSET))

        vince_advisory = cls(
            source_url=source_url,
            title=title,
            url=url,
            vuid=vuid,
            attribution=attribution,
            csaf_url=csaf_url,
            licence=licence,
            published=published,
            retrieved_at=retrieved_at,
            source=source,
            updated=updated,
        )

        vince_advisory.additional_properties = d
        return vince_advisory

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
