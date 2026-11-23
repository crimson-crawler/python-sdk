from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.distro_advisory_status import DistroAdvisoryStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="DistroAdvisory")


@_attrs_define
class DistroAdvisory:
    """One distro advisory row for a CVE, from SUSE CSAF-VEX, Ubuntu OpenVEX or Alpine secdb.

    A row is one (release, package, status, fixed_version). `status="unavailable"` marks a source that
    could not be read: it carries `error` and no release or package. That is an outage, never an absence.

        Attributes:
            attribution (str): Attribution: source, licence name and URL, and that the row is normalised.
            distro (str): Distribution: SUSE, Ubuntu or Alpine.
            licence (str): Licence of the source data: `CC-BY-4.0` (SUSE), `CC-BY-SA-4.0` (Ubuntu, Alpine).
            retrieved_at (str): UTC timestamp the source document was read.
            source (str): Source key: `suse_csaf_vex`, `ubuntu_openvex` or `alpine_secdb`.
            status (DistroAdvisoryStatus): `fixed`: a release carries the fix. `not_affected`: the release does not ship the
                vulnerable code. `needs_triage`: the distro is still investigating. `open`: affected, no fix published.
                `unavailable`: the source could not be read.
            error (None | str | Unset): Sanitised reason, only on `status=unavailable`.
            fixed_version (None | str | Unset): The version that fixes the package. Set only for `fixed`. SUSE gives
                `version-release`; Ubuntu and Alpine give the version as published.
            package (None | str | Unset): Source package name.
            release (None | str | Unset): Release stream: a SUSE product name, an Ubuntu distro qualifier (`jammy`, `esm-
                infra/bionic`) or an Alpine release (`v3.24`, `edge`).
            source_url (None | str | Unset): The upstream document this row was read from.
    """

    attribution: str
    distro: str
    licence: str
    retrieved_at: str
    source: str
    status: DistroAdvisoryStatus
    error: None | str | Unset = UNSET
    fixed_version: None | str | Unset = UNSET
    package: None | str | Unset = UNSET
    release: None | str | Unset = UNSET
    source_url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attribution = self.attribution

        distro = self.distro

        licence = self.licence

        retrieved_at = self.retrieved_at

        source = self.source

        status = self.status.value

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        fixed_version: None | str | Unset
        if isinstance(self.fixed_version, Unset):
            fixed_version = UNSET
        else:
            fixed_version = self.fixed_version

        package: None | str | Unset
        if isinstance(self.package, Unset):
            package = UNSET
        else:
            package = self.package

        release: None | str | Unset
        if isinstance(self.release, Unset):
            release = UNSET
        else:
            release = self.release

        source_url: None | str | Unset
        if isinstance(self.source_url, Unset):
            source_url = UNSET
        else:
            source_url = self.source_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "attribution": attribution,
                "distro": distro,
                "licence": licence,
                "retrieved_at": retrieved_at,
                "source": source,
                "status": status,
            }
        )
        if error is not UNSET:
            field_dict["error"] = error
        if fixed_version is not UNSET:
            field_dict["fixed_version"] = fixed_version
        if package is not UNSET:
            field_dict["package"] = package
        if release is not UNSET:
            field_dict["release"] = release
        if source_url is not UNSET:
            field_dict["source_url"] = source_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        attribution = d.pop("attribution")

        distro = d.pop("distro")

        licence = d.pop("licence")

        retrieved_at = d.pop("retrieved_at")

        source = d.pop("source")

        status = DistroAdvisoryStatus(d.pop("status"))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        def _parse_fixed_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fixed_version = _parse_fixed_version(d.pop("fixed_version", UNSET))

        def _parse_package(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        package = _parse_package(d.pop("package", UNSET))

        def _parse_release(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        release = _parse_release(d.pop("release", UNSET))

        def _parse_source_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_url = _parse_source_url(d.pop("source_url", UNSET))

        distro_advisory = cls(
            attribution=attribution,
            distro=distro,
            licence=licence,
            retrieved_at=retrieved_at,
            source=source,
            status=status,
            error=error,
            fixed_version=fixed_version,
            package=package,
            release=release,
            source_url=source_url,
        )

        distro_advisory.additional_properties = d
        return distro_advisory

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
