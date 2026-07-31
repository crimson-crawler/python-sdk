from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cve_reference import CVEReference


T = TypeVar("T", bound="CVEDetail")


@_attrs_define
class CVEDetail:
    """Vulnerability details including severity scoring, weakness classifications, and references.

    Attributes:
        cve_id (str): CVE identifier (e.g. CVE-2026-26929)
        cvss_score (float | None | Unset): CVSS base score (0.0-10.0)
        cvss_severity (None | str | Unset): Severity rating: none, low, medium, high, or critical
        cvss_v4_score (float | None | Unset): CVSS v4.0 base score (0.0-10.0), when available
        cvss_v4_severity (None | str | Unset): CVSS v4.0 severity rating (none/low/medium/high/critical)
        cvss_v4_vector (None | str | Unset): CVSS v4.0 vector string (CVSS:4.0/...)
        cvss_vector (None | str | Unset): CVSS vector string describing attack characteristics
        cvss_version (None | str | Unset): CVSS version used for scoring (e.g. '3.1')
        cwe_ids (list[str] | Unset): Associated weakness classification IDs (e.g. ['CWE-79'])
        description (None | str | Unset): Human-readable vulnerability description
        has_public_exploit (bool | Unset): Whether a public exploit or PoC is known to exist Default: False.
        modified (None | str | Unset): Last modification date (ISO 8601)
        poc_count (int | Unset): Number of proof-of-concept repositories on GitHub Default: 0.
        published (None | str | Unset): Publication date (ISO 8601)
        references (list[CVEReference] | Unset): Advisory and reference links
        weaponization_score (float | None | Unset): Computed weaponization risk score (0-100)
    """

    cve_id: str
    cvss_score: float | None | Unset = UNSET
    cvss_severity: None | str | Unset = UNSET
    cvss_v4_score: float | None | Unset = UNSET
    cvss_v4_severity: None | str | Unset = UNSET
    cvss_v4_vector: None | str | Unset = UNSET
    cvss_vector: None | str | Unset = UNSET
    cvss_version: None | str | Unset = UNSET
    cwe_ids: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    has_public_exploit: bool | Unset = False
    modified: None | str | Unset = UNSET
    poc_count: int | Unset = 0
    published: None | str | Unset = UNSET
    references: list[CVEReference] | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cve_reference import CVEReference

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

        cvss_v4_score: float | None | Unset
        if isinstance(self.cvss_v4_score, Unset):
            cvss_v4_score = UNSET
        else:
            cvss_v4_score = self.cvss_v4_score

        cvss_v4_severity: None | str | Unset
        if isinstance(self.cvss_v4_severity, Unset):
            cvss_v4_severity = UNSET
        else:
            cvss_v4_severity = self.cvss_v4_severity

        cvss_v4_vector: None | str | Unset
        if isinstance(self.cvss_v4_vector, Unset):
            cvss_v4_vector = UNSET
        else:
            cvss_v4_vector = self.cvss_v4_vector

        cvss_vector: None | str | Unset
        if isinstance(self.cvss_vector, Unset):
            cvss_vector = UNSET
        else:
            cvss_vector = self.cvss_vector

        cvss_version: None | str | Unset
        if isinstance(self.cvss_version, Unset):
            cvss_version = UNSET
        else:
            cvss_version = self.cvss_version

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        has_public_exploit = self.has_public_exploit

        modified: None | str | Unset
        if isinstance(self.modified, Unset):
            modified = UNSET
        else:
            modified = self.modified

        poc_count = self.poc_count

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = []
            for references_item_data in self.references:
                references_item = references_item_data.to_dict()
                references.append(references_item)

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
        if cvss_v4_score is not UNSET:
            field_dict["cvss_v4_score"] = cvss_v4_score
        if cvss_v4_severity is not UNSET:
            field_dict["cvss_v4_severity"] = cvss_v4_severity
        if cvss_v4_vector is not UNSET:
            field_dict["cvss_v4_vector"] = cvss_v4_vector
        if cvss_vector is not UNSET:
            field_dict["cvss_vector"] = cvss_vector
        if cvss_version is not UNSET:
            field_dict["cvss_version"] = cvss_version
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if description is not UNSET:
            field_dict["description"] = description
        if has_public_exploit is not UNSET:
            field_dict["has_public_exploit"] = has_public_exploit
        if modified is not UNSET:
            field_dict["modified"] = modified
        if poc_count is not UNSET:
            field_dict["poc_count"] = poc_count
        if published is not UNSET:
            field_dict["published"] = published
        if references is not UNSET:
            field_dict["references"] = references
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cve_reference import CVEReference

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

        def _parse_cvss_v4_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v4_score = _parse_cvss_v4_score(d.pop("cvss_v4_score", UNSET))

        def _parse_cvss_v4_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_severity = _parse_cvss_v4_severity(d.pop("cvss_v4_severity", UNSET))

        def _parse_cvss_v4_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_vector = _parse_cvss_v4_vector(d.pop("cvss_v4_vector", UNSET))

        def _parse_cvss_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_vector = _parse_cvss_vector(d.pop("cvss_vector", UNSET))

        def _parse_cvss_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_version = _parse_cvss_version(d.pop("cvss_version", UNSET))

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        has_public_exploit = d.pop("has_public_exploit", UNSET)

        def _parse_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified = _parse_modified(d.pop("modified", UNSET))

        poc_count = d.pop("poc_count", UNSET)

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        _references = d.pop("references", UNSET)
        references: list[CVEReference] | Unset = UNSET
        if _references is not UNSET:
            references = []
            for references_item_data in _references:
                references_item = CVEReference.from_dict(references_item_data)

                references.append(references_item)

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        cve_detail = cls(
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cvss_v4_score=cvss_v4_score,
            cvss_v4_severity=cvss_v4_severity,
            cvss_v4_vector=cvss_v4_vector,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            cwe_ids=cwe_ids,
            description=description,
            has_public_exploit=has_public_exploit,
            modified=modified,
            poc_count=poc_count,
            published=published,
            references=references,
            weaponization_score=weaponization_score,
        )

        cve_detail.additional_properties = d
        return cve_detail

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
