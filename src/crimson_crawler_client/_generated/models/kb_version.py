from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KBVersion")


@_attrs_define
class KBVersion:
    """Installed vs available revision of one knowledge base (read-only deployment metadata).

    Attributes:
        available_latest (None | str | Unset): Newest revision the knowledge base offers
        installed_latest (None | str | Unset): Latest revision actually loaded in the KB
        installed_versions (list[str] | Unset): All loaded revisions
        knowledge_base (str | Unset): KB name as requested in `sources` (e.g. 'attack', 'cwe') Default: ''.
        up_to_date (bool | None | Unset): True when the installed latest equals the newest available; null when either
            read failed
        vulmatch_object_count (int | None | Unset): Objects in the CVE-side partial copy of this KB, for the three KBs
            the CVE bundle renders names from (cwe/capec/attack). The copies are CVE-driven subsets — measured 2026-09-12:
            CWE 579 of 1,352, ATT&CK 172 of 4,296 — so a large gap means CVE-path answers may come from a partial copy. This
            is COVERAGE ONLY: it is not a freshness or synchronisation guarantee. Null for KBs with no CVE-side copy.
    """

    available_latest: None | str | Unset = UNSET
    installed_latest: None | str | Unset = UNSET
    installed_versions: list[str] | Unset = UNSET
    knowledge_base: str | Unset = ""
    up_to_date: bool | None | Unset = UNSET
    vulmatch_object_count: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        available_latest: None | str | Unset
        if isinstance(self.available_latest, Unset):
            available_latest = UNSET
        else:
            available_latest = self.available_latest

        installed_latest: None | str | Unset
        if isinstance(self.installed_latest, Unset):
            installed_latest = UNSET
        else:
            installed_latest = self.installed_latest

        installed_versions: list[str] | Unset = UNSET
        if not isinstance(self.installed_versions, Unset):
            installed_versions = self.installed_versions

        knowledge_base = self.knowledge_base

        up_to_date: bool | None | Unset
        if isinstance(self.up_to_date, Unset):
            up_to_date = UNSET
        else:
            up_to_date = self.up_to_date

        vulmatch_object_count: int | None | Unset
        if isinstance(self.vulmatch_object_count, Unset):
            vulmatch_object_count = UNSET
        else:
            vulmatch_object_count = self.vulmatch_object_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if available_latest is not UNSET:
            field_dict["available_latest"] = available_latest
        if installed_latest is not UNSET:
            field_dict["installed_latest"] = installed_latest
        if installed_versions is not UNSET:
            field_dict["installed_versions"] = installed_versions
        if knowledge_base is not UNSET:
            field_dict["knowledge_base"] = knowledge_base
        if up_to_date is not UNSET:
            field_dict["up_to_date"] = up_to_date
        if vulmatch_object_count is not UNSET:
            field_dict["vulmatch_object_count"] = vulmatch_object_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_available_latest(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        available_latest = _parse_available_latest(d.pop("available_latest", UNSET))

        def _parse_installed_latest(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        installed_latest = _parse_installed_latest(d.pop("installed_latest", UNSET))

        installed_versions = cast(list[str], d.pop("installed_versions", UNSET))

        knowledge_base = d.pop("knowledge_base", UNSET)

        def _parse_up_to_date(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        up_to_date = _parse_up_to_date(d.pop("up_to_date", UNSET))

        def _parse_vulmatch_object_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        vulmatch_object_count = _parse_vulmatch_object_count(d.pop("vulmatch_object_count", UNSET))

        kb_version = cls(
            available_latest=available_latest,
            installed_latest=installed_latest,
            installed_versions=installed_versions,
            knowledge_base=knowledge_base,
            up_to_date=up_to_date,
            vulmatch_object_count=vulmatch_object_count,
        )

        kb_version.additional_properties = d
        return kb_version

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
