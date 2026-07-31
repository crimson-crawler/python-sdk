from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.enrich_cve_response import EnrichCVEResponse
    from ..models.error_detail import ErrorDetail
    from ..models.osv_advisory import OSVAdvisory


T = TypeVar("T", bound="EnrichPackageResponse")


@_attrs_define
class EnrichPackageResponse:
    """Open-source package enrichment — OSV.dev advisories + full multi-source CVE enrichment.

    The package-ecosystem sibling of `EnrichProductResponse`: OSV gives the advisories, and the CVEs
    they alias are enriched through the same multi-source CWE→CAPEC→ATT&CK + EPSS/KEV chain
    as `enrich/product`'s nested CVEs — gated by the CVE-chain `include` options.

        Attributes:
            ecosystem (str): Canonical OSV ecosystem queried
            package (str): Package name queried
            advisories (list[OSVAdvisory] | Unset): Matched OSV advisories (CVE-aliased first, then by id)
            cves (list[EnrichCVEResponse] | Unset): Full multi-source enrichment for each CVE the advisories alias — same
                nested shape as `enrich/product`'s `cves`. Populated when the request carries CVE-chain `include` options
                (epss/kev/cwe/capec/techniques/…); capped per request.
            errors (list[ErrorDetail] | Unset): Partial failure details
            highest_weaponization_score (float | None | Unset): Max 0-100 weaponization score across the package's enriched
                CVEs
            version (None | str | Unset): Version filter applied (if any)
            vulnerability_count (int | Unset): Number of advisories matched Default: 0.
    """

    ecosystem: str
    package: str
    advisories: list[OSVAdvisory] | Unset = UNSET
    cves: list[EnrichCVEResponse] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    highest_weaponization_score: float | None | Unset = UNSET
    version: None | str | Unset = UNSET
    vulnerability_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.enrich_cve_response import EnrichCVEResponse
        from ..models.error_detail import ErrorDetail
        from ..models.osv_advisory import OSVAdvisory

        ecosystem = self.ecosystem

        package = self.package

        advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.advisories, Unset):
            advisories = []
            for advisories_item_data in self.advisories:
                advisories_item = advisories_item_data.to_dict()
                advisories.append(advisories_item)

        cves: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cves, Unset):
            cves = []
            for cves_item_data in self.cves:
                cves_item = cves_item_data.to_dict()
                cves.append(cves_item)

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        highest_weaponization_score: float | None | Unset
        if isinstance(self.highest_weaponization_score, Unset):
            highest_weaponization_score = UNSET
        else:
            highest_weaponization_score = self.highest_weaponization_score

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        vulnerability_count = self.vulnerability_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ecosystem": ecosystem,
                "package": package,
            }
        )
        if advisories is not UNSET:
            field_dict["advisories"] = advisories
        if cves is not UNSET:
            field_dict["cves"] = cves
        if errors is not UNSET:
            field_dict["errors"] = errors
        if highest_weaponization_score is not UNSET:
            field_dict["highest_weaponization_score"] = highest_weaponization_score
        if version is not UNSET:
            field_dict["version"] = version
        if vulnerability_count is not UNSET:
            field_dict["vulnerability_count"] = vulnerability_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.enrich_cve_response import EnrichCVEResponse
        from ..models.error_detail import ErrorDetail
        from ..models.osv_advisory import OSVAdvisory

        d = dict(src_dict)
        ecosystem = d.pop("ecosystem")

        package = d.pop("package")

        _advisories = d.pop("advisories", UNSET)
        advisories: list[OSVAdvisory] | Unset = UNSET
        if _advisories is not UNSET:
            advisories = []
            for advisories_item_data in _advisories:
                advisories_item = OSVAdvisory.from_dict(advisories_item_data)

                advisories.append(advisories_item)

        _cves = d.pop("cves", UNSET)
        cves: list[EnrichCVEResponse] | Unset = UNSET
        if _cves is not UNSET:
            cves = []
            for cves_item_data in _cves:
                cves_item = EnrichCVEResponse.from_dict(cves_item_data)

                cves.append(cves_item)

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        def _parse_highest_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        highest_weaponization_score = _parse_highest_weaponization_score(d.pop("highest_weaponization_score", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        vulnerability_count = d.pop("vulnerability_count", UNSET)

        enrich_package_response = cls(
            ecosystem=ecosystem,
            package=package,
            advisories=advisories,
            cves=cves,
            errors=errors,
            highest_weaponization_score=highest_weaponization_score,
            version=version,
            vulnerability_count=vulnerability_count,
        )

        enrich_package_response.additional_properties = d
        return enrich_package_response

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
