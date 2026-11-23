from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.osv_affected_range_ecosystem_specific import OSVAffectedRangeEcosystemSpecific


T = TypeVar("T", bound="OSVAffectedRange")


@_attrs_define
class OSVAffectedRange:
    """One affected version range for the queried package (from an OSV advisory's `affected[]`).

    Attributes:
        cpes (list[None | str] | None | Unset): CPE matchstrings this range corresponds to, from the range's own
            `database_specific` (CVE-namespace advisories annotate each range with one) — the only place an OSV advisory
            names a CPE
        ecosystem (None | str | Unset): The package ecosystem THIS range belongs to
        ecosystem_specific (OSVAffectedRangeEcosystemSpecific | Unset): THIS entry's own `ecosystem_specific` block —
            the ecosystem-private detail (for Go: the vulnerable import path and symbols). On a multi-package advisory it
            keeps each package's block with that package's ranges instead of collapsing them into one advisory-level answer
            (the response-level `ecosystem_specific` stays empty in that case)
        fixed (None | str | Unset): Version the vulnerability was fixed in (if known); a COMMIT SHA on a `GIT` range
        introduced (None | str | Unset): Version it was introduced in ('0' = from the start). On a `GIT` range this is a
            COMMIT SHA, not a release version — read it together with `repo`
        last_affected (None | str | Unset): Last version known to be affected (when no fix exists)
        limit (None | str | Unset): Exclusive upper boundary of the affected range, not a fix
        package_name (None | str | Unset): The package this range belongs to. Set ONLY on advisories covering more than
            one package — where a range would otherwise not say which of them it describes (a Go advisory routinely covers a
            module AND `stdlib`); null when the advisory names a single package, which the response already identifies
        package_purl (None | str | Unset): The Package URL of the package THIS range belongs to, so a consumer can join
            a range to its own SBOM entry without reading `affected_packages`. On a single-package advisory it repeats the
            response-level `package_purl`; on a multi-package one it is what tells the ranges apart
        repo (None | str | Unset): The repository a `GIT` range's commit SHAs belong to (`range.repo`) — without it the
            commits are unresolvable. Null on version ranges, which need no repository
        type_ (None | str | Unset): Range type — SEMVER, ECOSYSTEM, or GIT Default: ''.
        versions (list[None | str] | Unset): Explicitly affected versions, for advisories that enumerate versions
            instead of ranges. Populated alone (with an empty `type`) when the advisory declares no ranges — those
            advisories otherwise produced no affected rows at all.
    """

    cpes: list[None | str] | None | Unset = UNSET
    ecosystem: None | str | Unset = UNSET
    ecosystem_specific: OSVAffectedRangeEcosystemSpecific | Unset = UNSET
    fixed: None | str | Unset = UNSET
    introduced: None | str | Unset = UNSET
    last_affected: None | str | Unset = UNSET
    limit: None | str | Unset = UNSET
    package_name: None | str | Unset = UNSET
    package_purl: None | str | Unset = UNSET
    repo: None | str | Unset = UNSET
    type_: None | str | Unset = ""
    versions: list[None | str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.osv_affected_range_ecosystem_specific import OSVAffectedRangeEcosystemSpecific  # noqa: PLC0415

        cpes: list[None | str] | None | Unset
        if isinstance(self.cpes, Unset):
            cpes = UNSET
        elif isinstance(self.cpes, list):
            cpes = []
            for cpes_type_0_item_data in self.cpes:
                cpes_type_0_item: None | str
                cpes_type_0_item = cpes_type_0_item_data
                cpes.append(cpes_type_0_item)

        else:
            cpes = self.cpes

        ecosystem: None | str | Unset
        if isinstance(self.ecosystem, Unset):
            ecosystem = UNSET
        else:
            ecosystem = self.ecosystem

        ecosystem_specific: dict[str, Any] | Unset = UNSET
        if not isinstance(self.ecosystem_specific, Unset):
            ecosystem_specific = self.ecosystem_specific.to_dict()

        fixed: None | str | Unset
        if isinstance(self.fixed, Unset):
            fixed = UNSET
        else:
            fixed = self.fixed

        introduced: None | str | Unset
        if isinstance(self.introduced, Unset):
            introduced = UNSET
        else:
            introduced = self.introduced

        last_affected: None | str | Unset
        if isinstance(self.last_affected, Unset):
            last_affected = UNSET
        else:
            last_affected = self.last_affected

        limit: None | str | Unset
        if isinstance(self.limit, Unset):
            limit = UNSET
        else:
            limit = self.limit

        package_name: None | str | Unset
        if isinstance(self.package_name, Unset):
            package_name = UNSET
        else:
            package_name = self.package_name

        package_purl: None | str | Unset
        if isinstance(self.package_purl, Unset):
            package_purl = UNSET
        else:
            package_purl = self.package_purl

        repo: None | str | Unset
        if isinstance(self.repo, Unset):
            repo = UNSET
        else:
            repo = self.repo

        type_: None | str | Unset
        if isinstance(self.type_, Unset):
            type_ = UNSET
        else:
            type_ = self.type_

        versions: list[None | str] | Unset = UNSET
        if not isinstance(self.versions, Unset):
            versions = []
            for versions_item_data in self.versions:
                versions_item: None | str
                versions_item = versions_item_data
                versions.append(versions_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cpes is not UNSET:
            field_dict["cpes"] = cpes
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if ecosystem_specific is not UNSET:
            field_dict["ecosystem_specific"] = ecosystem_specific
        if fixed is not UNSET:
            field_dict["fixed"] = fixed
        if introduced is not UNSET:
            field_dict["introduced"] = introduced
        if last_affected is not UNSET:
            field_dict["last_affected"] = last_affected
        if limit is not UNSET:
            field_dict["limit"] = limit
        if package_name is not UNSET:
            field_dict["package_name"] = package_name
        if package_purl is not UNSET:
            field_dict["package_purl"] = package_purl
        if repo is not UNSET:
            field_dict["repo"] = repo
        if type_ is not UNSET:
            field_dict["type"] = type_
        if versions is not UNSET:
            field_dict["versions"] = versions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.osv_affected_range_ecosystem_specific import OSVAffectedRangeEcosystemSpecific  # noqa: PLC0415

        d = dict(src_dict)

        def _parse_cpes(data: object) -> list[None | str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                cpes_type_0 = []
                _cpes_type_0 = data
                for cpes_type_0_item_data in _cpes_type_0:

                    def _parse_cpes_type_0_item(data: object) -> None | str:
                        if data is None:
                            return data
                        return cast(None | str, data)

                    cpes_type_0_item = _parse_cpes_type_0_item(cpes_type_0_item_data)

                    cpes_type_0.append(cpes_type_0_item)

                return cpes_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[None | str] | None | Unset, data)

        cpes = _parse_cpes(d.pop("cpes", UNSET))

        def _parse_ecosystem(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ecosystem = _parse_ecosystem(d.pop("ecosystem", UNSET))

        _ecosystem_specific = d.pop("ecosystem_specific", UNSET)
        ecosystem_specific: OSVAffectedRangeEcosystemSpecific | Unset
        if isinstance(_ecosystem_specific, Unset):
            ecosystem_specific = UNSET
        else:
            ecosystem_specific = OSVAffectedRangeEcosystemSpecific.from_dict(_ecosystem_specific)

        def _parse_fixed(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fixed = _parse_fixed(d.pop("fixed", UNSET))

        def _parse_introduced(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        introduced = _parse_introduced(d.pop("introduced", UNSET))

        def _parse_last_affected(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_affected = _parse_last_affected(d.pop("last_affected", UNSET))

        def _parse_limit(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        limit = _parse_limit(d.pop("limit", UNSET))

        def _parse_package_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        package_name = _parse_package_name(d.pop("package_name", UNSET))

        def _parse_package_purl(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        package_purl = _parse_package_purl(d.pop("package_purl", UNSET))

        def _parse_repo(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        repo = _parse_repo(d.pop("repo", UNSET))

        def _parse_type_(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        type_ = _parse_type_(d.pop("type", UNSET))

        _versions = d.pop("versions", UNSET)
        versions: list[None | str] | Unset = UNSET
        if _versions is not UNSET:
            versions = []
            for versions_item_data in _versions:

                def _parse_versions_item(data: object) -> None | str:
                    if data is None:
                        return data
                    return cast(None | str, data)

                versions_item = _parse_versions_item(versions_item_data)

                versions.append(versions_item)

        osv_affected_range = cls(
            cpes=cpes,
            ecosystem=ecosystem,
            ecosystem_specific=ecosystem_specific,
            fixed=fixed,
            introduced=introduced,
            last_affected=last_affected,
            limit=limit,
            package_name=package_name,
            package_purl=package_purl,
            repo=repo,
            type_=type_,
            versions=versions,
        )

        osv_affected_range.additional_properties = d
        return osv_affected_range

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
