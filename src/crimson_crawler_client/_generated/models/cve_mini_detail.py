from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CVEMiniDetail")


@_attrs_define
class CVEMiniDetail:
    """Lightweight CVE summary for cross-reference results.

    Attributes:
        cve_id (str): CVE identifier
        cvss_score (float | None | Unset): CVSS base score
        cvss_severity (None | str | Unset): Severity: none, low, medium, high, critical
        description (None | str | Unset): Brief description
        epss_score (float | None | Unset): EPSS exploitation probability
        in_kev (bool | Unset): In the Known Exploited Vulnerabilities catalog Default: False.
        poc_count (int | Unset): Number of PoC repositories on GitHub Default: 0.
        shared_cwes (list[str] | Unset): CWE IDs shared with the source CVE
        shared_techniques (list[str] | Unset): Technique IDs shared with the source CVE
        similarity_score (float | None | Unset): Jaccard similarity to the source CVE (0.0-1.0)
        weaponization_score (float | None | Unset): Computed risk score (0-100)
    """

    cve_id: str
    cvss_score: float | None | Unset = UNSET
    cvss_severity: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    epss_score: float | None | Unset = UNSET
    in_kev: bool | Unset = False
    poc_count: int | Unset = 0
    shared_cwes: list[str] | Unset = UNSET
    shared_techniques: list[str] | Unset = UNSET
    similarity_score: float | None | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        cvss_severity: None | str | Unset
        if isinstance(self.cvss_severity, Unset):
            cvss_severity = UNSET
        else:
            cvss_severity = self.cvss_severity

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        epss_score: float | None | Unset
        if isinstance(self.epss_score, Unset):
            epss_score = UNSET
        else:
            epss_score = self.epss_score

        in_kev = self.in_kev

        poc_count = self.poc_count

        shared_cwes: list[str] | Unset = UNSET
        if not isinstance(self.shared_cwes, Unset):
            shared_cwes = self.shared_cwes

        shared_techniques: list[str] | Unset = UNSET
        if not isinstance(self.shared_techniques, Unset):
            shared_techniques = self.shared_techniques

        similarity_score: float | None | Unset
        if isinstance(self.similarity_score, Unset):
            similarity_score = UNSET
        else:
            similarity_score = self.similarity_score

        weaponization_score: float | None | Unset
        if isinstance(self.weaponization_score, Unset):
            weaponization_score = UNSET
        else:
            weaponization_score = self.weaponization_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if cvss_severity is not UNSET:
            field_dict["cvss_severity"] = cvss_severity
        if description is not UNSET:
            field_dict["description"] = description
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if in_kev is not UNSET:
            field_dict["in_kev"] = in_kev
        if poc_count is not UNSET:
            field_dict["poc_count"] = poc_count
        if shared_cwes is not UNSET:
            field_dict["shared_cwes"] = shared_cwes
        if shared_techniques is not UNSET:
            field_dict["shared_techniques"] = shared_techniques
        if similarity_score is not UNSET:
            field_dict["similarity_score"] = similarity_score
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_cvss_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_severity = _parse_cvss_severity(d.pop("cvss_severity", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_epss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_score = _parse_epss_score(d.pop("epss_score", UNSET))

        in_kev = d.pop("in_kev", UNSET)

        poc_count = d.pop("poc_count", UNSET)

        shared_cwes = cast(list[str], d.pop("shared_cwes", UNSET))

        shared_techniques = cast(list[str], d.pop("shared_techniques", UNSET))

        def _parse_similarity_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        similarity_score = _parse_similarity_score(d.pop("similarity_score", UNSET))

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        cve_mini_detail = cls(
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            description=description,
            epss_score=epss_score,
            in_kev=in_kev,
            poc_count=poc_count,
            shared_cwes=shared_cwes,
            shared_techniques=shared_techniques,
            similarity_score=similarity_score,
            weaponization_score=weaponization_score,
        )

        cve_mini_detail.additional_properties = d
        return cve_mini_detail

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
