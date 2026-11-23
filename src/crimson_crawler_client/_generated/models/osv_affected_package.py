from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.osv_affected_package_database_specific import OSVAffectedPackageDatabaseSpecific
    from ..models.osv_affected_package_ecosystem_specific import OSVAffectedPackageEcosystemSpecific


T = TypeVar("T", bound="OSVAffectedPackage")


@_attrs_define
class OSVAffectedPackage:
    """One `affected[]` entry of an advisory — the package it names, with that entry's own metadata.

    The per-package association OSV states and a single advisory-level block cannot carry: an
    advisory routinely covers several packages (measured 2026-09-16: GO-2023-2102 covers
    `golang.org/x/net` AND `stdlib`, 224 of 495 probed records multi-entry), each with its own purl
    and its own `ecosystem_specific`. Entries that enumerate neither ranges nor versions are still
    published here — that is the only place their metadata survives.

        Attributes:
            database_specific (OSVAffectedPackageDatabaseSpecific | Unset): The entry's own `database_specific` block
                (severity, CPEs, …)
            ecosystem (None | str | Unset): Ecosystem the entry names (e.g. 'Go', 'npm') Default: ''.
            ecosystem_specific (OSVAffectedPackageEcosystemSpecific | Unset): The entry's own `ecosystem_specific` block
                (import paths, symbols, …)
            has_ranges (bool | Unset): Whether the entry declares version ranges Default: False.
            has_versions (bool | Unset): Whether the entry enumerates explicit affected versions Default: False.
            name (None | str | Unset): Package name the entry names Default: ''.
            purl (None | str | Unset): The entry's Package URL, when OSV publishes one
    """

    database_specific: OSVAffectedPackageDatabaseSpecific | Unset = UNSET
    ecosystem: None | str | Unset = ""
    ecosystem_specific: OSVAffectedPackageEcosystemSpecific | Unset = UNSET
    has_ranges: bool | Unset = False
    has_versions: bool | Unset = False
    name: None | str | Unset = ""
    purl: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.osv_affected_package_database_specific import OSVAffectedPackageDatabaseSpecific  # noqa: PLC0415
        from ..models.osv_affected_package_ecosystem_specific import (
            OSVAffectedPackageEcosystemSpecific,  # noqa: PLC0415
        )

        database_specific: dict[str, Any] | Unset = UNSET
        if not isinstance(self.database_specific, Unset):
            database_specific = self.database_specific.to_dict()

        ecosystem: None | str | Unset
        if isinstance(self.ecosystem, Unset):
            ecosystem = UNSET
        else:
            ecosystem = self.ecosystem

        ecosystem_specific: dict[str, Any] | Unset = UNSET
        if not isinstance(self.ecosystem_specific, Unset):
            ecosystem_specific = self.ecosystem_specific.to_dict()

        has_ranges = self.has_ranges

        has_versions = self.has_versions

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        purl: None | str | Unset
        if isinstance(self.purl, Unset):
            purl = UNSET
        else:
            purl = self.purl

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if database_specific is not UNSET:
            field_dict["database_specific"] = database_specific
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if ecosystem_specific is not UNSET:
            field_dict["ecosystem_specific"] = ecosystem_specific
        if has_ranges is not UNSET:
            field_dict["has_ranges"] = has_ranges
        if has_versions is not UNSET:
            field_dict["has_versions"] = has_versions
        if name is not UNSET:
            field_dict["name"] = name
        if purl is not UNSET:
            field_dict["purl"] = purl

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.osv_affected_package_database_specific import OSVAffectedPackageDatabaseSpecific  # noqa: PLC0415
        from ..models.osv_affected_package_ecosystem_specific import (
            OSVAffectedPackageEcosystemSpecific,  # noqa: PLC0415
        )

        d = dict(src_dict)
        _database_specific = d.pop("database_specific", UNSET)
        database_specific: OSVAffectedPackageDatabaseSpecific | Unset
        if isinstance(_database_specific, Unset):
            database_specific = UNSET
        else:
            database_specific = OSVAffectedPackageDatabaseSpecific.from_dict(_database_specific)

        def _parse_ecosystem(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ecosystem = _parse_ecosystem(d.pop("ecosystem", UNSET))

        _ecosystem_specific = d.pop("ecosystem_specific", UNSET)
        ecosystem_specific: OSVAffectedPackageEcosystemSpecific | Unset
        if isinstance(_ecosystem_specific, Unset):
            ecosystem_specific = UNSET
        else:
            ecosystem_specific = OSVAffectedPackageEcosystemSpecific.from_dict(_ecosystem_specific)

        has_ranges = d.pop("has_ranges", UNSET)

        has_versions = d.pop("has_versions", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_purl(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        purl = _parse_purl(d.pop("purl", UNSET))

        osv_affected_package = cls(
            database_specific=database_specific,
            ecosystem=ecosystem,
            ecosystem_specific=ecosystem_specific,
            has_ranges=has_ranges,
            has_versions=has_versions,
            name=name,
            purl=purl,
        )

        osv_affected_package.additional_properties = d
        return osv_affected_package

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
