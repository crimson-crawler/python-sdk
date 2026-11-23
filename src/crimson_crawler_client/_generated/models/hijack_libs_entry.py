from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="HijackLibsEntry")


@_attrs_define
class HijackLibsEntry:
    """One HijackLibs DLL hijack, reduced to facts: DLL, vendor, paths, types and ATT&CK ids.

    No author, resource list or prose is reproduced from the GPL-3.0 catalogue.

        Attributes:
            name (str): DLL name as the catalogue publishes it
            project_url (str): The HijackLibs project page
            source_url (str): The HijackLibs repository URL
            cve_ids (list[str] | Unset): CVE ids the entry names
            dataset_version (None | str | Unset): Tarball sha256 the projection came from
            entry_types (list[str] | Unset): Hijack types (Sideloading, Search Order, Phantom, Environment Variable)
            executable_paths (list[str] | Unset): Executables whose DLL load can be hijacked
            expected_locations (list[str] | Unset): Directories the library is expected to load from
            source (str | Unset): Stable source label Default: 'hijacklibs'.
            technique_ids (list[str] | Unset): ATT&CK technique ids the entry's hijack types map onto
            vendor (None | str | Unset): Vendor that ships the hijackable library
    """

    name: str
    project_url: str
    source_url: str
    cve_ids: list[str] | Unset = UNSET
    dataset_version: None | str | Unset = UNSET
    entry_types: list[str] | Unset = UNSET
    executable_paths: list[str] | Unset = UNSET
    expected_locations: list[str] | Unset = UNSET
    source: str | Unset = "hijacklibs"
    technique_ids: list[str] | Unset = UNSET
    vendor: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        project_url = self.project_url

        source_url = self.source_url

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        dataset_version: None | str | Unset
        if isinstance(self.dataset_version, Unset):
            dataset_version = UNSET
        else:
            dataset_version = self.dataset_version

        entry_types: list[str] | Unset = UNSET
        if not isinstance(self.entry_types, Unset):
            entry_types = self.entry_types

        executable_paths: list[str] | Unset = UNSET
        if not isinstance(self.executable_paths, Unset):
            executable_paths = self.executable_paths

        expected_locations: list[str] | Unset = UNSET
        if not isinstance(self.expected_locations, Unset):
            expected_locations = self.expected_locations

        source = self.source

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "project_url": project_url,
                "source_url": source_url,
            }
        )
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if dataset_version is not UNSET:
            field_dict["dataset_version"] = dataset_version
        if entry_types is not UNSET:
            field_dict["entry_types"] = entry_types
        if executable_paths is not UNSET:
            field_dict["executable_paths"] = executable_paths
        if expected_locations is not UNSET:
            field_dict["expected_locations"] = expected_locations
        if source is not UNSET:
            field_dict["source"] = source
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids
        if vendor is not UNSET:
            field_dict["vendor"] = vendor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        project_url = d.pop("project_url")

        source_url = d.pop("source_url")

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_dataset_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dataset_version = _parse_dataset_version(d.pop("dataset_version", UNSET))

        entry_types = cast(list[str], d.pop("entry_types", UNSET))

        executable_paths = cast(list[str], d.pop("executable_paths", UNSET))

        expected_locations = cast(list[str], d.pop("expected_locations", UNSET))

        source = d.pop("source", UNSET)

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        hijack_libs_entry = cls(
            name=name,
            project_url=project_url,
            source_url=source_url,
            cve_ids=cve_ids,
            dataset_version=dataset_version,
            entry_types=entry_types,
            executable_paths=executable_paths,
            expected_locations=expected_locations,
            source=source,
            technique_ids=technique_ids,
            vendor=vendor,
        )

        hijack_libs_entry.additional_properties = d
        return hijack_libs_entry

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
