from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LOLDriver")


@_attrs_define
class LOLDriver:
    """One LOLDrivers entry exercising an ATT&CK technique.

    LOLDrivers ships (Apache-2.0) through the seeded `lotl` token together with the
    facts-only GTFOBins and HijackLibs projections (`gtfobins_binaries`, `hijacklibs_entries`);
    the GPL-3.0 picks join on the committed function/type → ATT&CK map, never on a name.

        Attributes:
            id (str): LOLDrivers entry id
            name (str): Driver name
            source_url (str): The LOLDrivers dataset URL
            category (None | str | Unset): Entry category
            cve_ids (list[str] | Unset): CVE ids the entry's samples name
            dataset_version (None | str | Unset): Corpus revision the index recorded
            description (None | str | Unset): What the driver's abuse looks like
            known_vulnerable (bool | None | Unset): Whether LOLDrivers marks the sample vulnerable
            source (str | Unset): Stable source label Default: 'lotl'.
            technique_ids (list[str] | Unset): ATT&CK technique ids the entry names
    """

    id: str
    name: str
    source_url: str
    category: None | str | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    dataset_version: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    known_vulnerable: bool | None | Unset = UNSET
    source: str | Unset = "lotl"
    technique_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        source_url = self.source_url

        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        else:
            category = self.category

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        dataset_version: None | str | Unset
        if isinstance(self.dataset_version, Unset):
            dataset_version = UNSET
        else:
            dataset_version = self.dataset_version

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        known_vulnerable: bool | None | Unset
        if isinstance(self.known_vulnerable, Unset):
            known_vulnerable = UNSET
        else:
            known_vulnerable = self.known_vulnerable

        source = self.source

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "source_url": source_url,
            }
        )
        if category is not UNSET:
            field_dict["category"] = category
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if dataset_version is not UNSET:
            field_dict["dataset_version"] = dataset_version
        if description is not UNSET:
            field_dict["description"] = description
        if known_vulnerable is not UNSET:
            field_dict["known_vulnerable"] = known_vulnerable
        if source is not UNSET:
            field_dict["source"] = source
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        source_url = d.pop("source_url")

        def _parse_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_dataset_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dataset_version = _parse_dataset_version(d.pop("dataset_version", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_known_vulnerable(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        known_vulnerable = _parse_known_vulnerable(d.pop("known_vulnerable", UNSET))

        source = d.pop("source", UNSET)

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        lol_driver = cls(
            id=id,
            name=name,
            source_url=source_url,
            category=category,
            cve_ids=cve_ids,
            dataset_version=dataset_version,
            description=description,
            known_vulnerable=known_vulnerable,
            source=source,
            technique_ids=technique_ids,
        )

        lol_driver.additional_properties = d
        return lol_driver

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
