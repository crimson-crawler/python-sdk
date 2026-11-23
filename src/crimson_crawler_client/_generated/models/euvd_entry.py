from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EUVDEntry")


@_attrs_define
class EUVDEntry:
    """An ENISA EU Vulnerability Database entry for a CVE.

    Attributes:
        euvd_id (str): EUVD id (EUVD-YYYY-NNNNN)
        source_url (str): The EUVD API URL
        cve_ids (list[str] | Unset): CVE ids the entry aliases
        cvss_score (float | None | Unset): Base score
        exploited (bool | None | Unset): Whether ENISA records exploitation
        published (None | str | Unset): Publication date
        retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
        source (str | Unset): Stable source label Default: 'euvd'.
        updated (None | str | Unset): Last update date
        url (None | str | Unset): The entry's public page
    """

    euvd_id: str
    source_url: str
    cve_ids: list[str] | Unset = UNSET
    cvss_score: float | None | Unset = UNSET
    exploited: bool | None | Unset = UNSET
    published: None | str | Unset = UNSET
    retrieved_at: str | Unset = ""
    source: str | Unset = "euvd"
    updated: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        euvd_id = self.euvd_id

        source_url = self.source_url

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        exploited: bool | None | Unset
        if isinstance(self.exploited, Unset):
            exploited = UNSET
        else:
            exploited = self.exploited

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

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "euvd_id": euvd_id,
                "source_url": source_url,
            }
        )
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if exploited is not UNSET:
            field_dict["exploited"] = exploited
        if published is not UNSET:
            field_dict["published"] = published
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if source is not UNSET:
            field_dict["source"] = source
        if updated is not UNSET:
            field_dict["updated"] = updated
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        euvd_id = d.pop("euvd_id")

        source_url = d.pop("source_url")

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_exploited(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        exploited = _parse_exploited(d.pop("exploited", UNSET))

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

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        euvd_entry = cls(
            euvd_id=euvd_id,
            source_url=source_url,
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            exploited=exploited,
            published=published,
            retrieved_at=retrieved_at,
            source=source,
            updated=updated,
            url=url,
        )

        euvd_entry.additional_properties = d
        return euvd_entry

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
