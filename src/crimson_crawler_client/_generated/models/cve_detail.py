from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cve_reference import CVEReference
    from ..models.cvss_alternate import CVSSAlternate


T = TypeVar("T", bound="CVEDetail")


@_attrs_define
class CVEDetail:
    """Vulnerability details including severity scoring, weakness classifications, and references.

    Attributes:
        cve_id (str): CVE identifier (e.g. CVE-2026-26929)
        cna_contact (None | str | Unset): CNA contact information (usually the security@ alias)
        cna_name (None | str | Unset): Resolved name of the assigning CNA (e.g. 'Apache Software Foundation')
        created_by_ref (None | str | Unset): STIX identity id of the CNA that assigned this CVE (100% of the corpus
            carries one)
        cvss_alternates (list[CVSSAlternate] | Unset): Alternate published scorings for the same CVSS version — every
            entry other than the one surfaced in `cvss_v*_score`. Carries the `entry_type` Primary/Secondary discriminator.
            231 of 3,000 sampled CVEs have at least one; 122 of those a different base score AND severity band.
        cvss_v2_entry_type (None | str | Unset): Role of the surfaced CVSS v2.x entry in NVD's container: `Primary` (the
            record's primary reading) or `Secondary`. Not authorship — `cvss_v2_source` is who scored it
        cvss_v2_exploitability_score (float | None | Unset): CVSS v2.0 exploitability sub-score (0.0-10.0) — the ease of
            exploiting this CVE
        cvss_v2_impact_score (float | None | Unset): CVSS v2.0 impact sub-score (0.0-10.0) — the damage a successful
            exploit causes
        cvss_v2_score (float | None | Unset): CVSS v2.0 base score (0.0-10.0), when the CVE carries a v2.0 score
        cvss_v2_severity (None | str | Unset): CVSS v2.0 severity rating, in the source's own casing (LOW/MEDIUM/HIGH)
        cvss_v2_source (None | str | Unset): Who scored this CVE under CVSS v2.0 (the CNA/advisory identifier, e.g.
            'nvd@nist.gov')
        cvss_v2_vector (None | str | Unset): CVSS v2.0 vector string (e.g. 'AV:N/AC:L/Au:N/C:P/I:P/A:P')
        cvss_v3_entry_type (None | str | Unset): Role of the surfaced CVSS v3.x entry in NVD's container: `Primary` (the
            record's primary reading) or `Secondary`. Not authorship — `cvss_v3_source` is who scored it
        cvss_v3_exploitability_score (float | None | Unset): CVSS v3.x exploitability sub-score (0.0-10.0) — the ease of
            exploiting this CVE
        cvss_v3_impact_score (float | None | Unset): CVSS v3.x impact sub-score (0.0-10.0) — the damage a successful
            exploit causes
        cvss_v3_score (float | None | Unset): CVSS v3.x base score (0.0-10.0), when available
        cvss_v3_severity (None | str | Unset): CVSS v3.x severity rating, in the source's own casing
            (NONE/LOW/MEDIUM/HIGH/CRITICAL)
        cvss_v3_source (None | str | Unset): Who scored this CVE under CVSS v3.x (the CNA/advisory identifier, e.g.
            'nvd@nist.gov')
        cvss_v3_vector (None | str | Unset): CVSS v3.x vector string (CVSS:3.1/... or CVSS:3.0/...)
        cvss_v3_version (None | str | Unset): Which v3 revision `cvss_v3_*` holds — '3.1' or '3.0' (3.1 preferred when
            both are published)
        cvss_v4_entry_type (None | str | Unset): Role of the surfaced CVSS v4.x entry in NVD's container: `Primary` (the
            record's primary reading) or `Secondary`. Not authorship — `cvss_v4_source` is who scored it
        cvss_v4_score (float | None | Unset): CVSS v4.0 base score (0.0-10.0), when available
        cvss_v4_severity (None | str | Unset): CVSS v4.0 severity rating, in the source's own casing
            (NONE/LOW/MEDIUM/HIGH/CRITICAL)
        cvss_v4_source (None | str | Unset): Who scored this CVE under CVSS v4.0 (the CNA/advisory identifier, e.g.
            'nvd@nist.gov')
        cvss_v4_vector (None | str | Unset): CVSS v4.0 vector string (CVSS:4.0/...)
        cwe_ids (list[str] | Unset): Associated weakness classification IDs (e.g. ['CWE-79'])
        description (None | str | Unset): Human-readable vulnerability description
        epss_percentile (float | None | Unset): EPSS percentile rank among all scored CVEs (0.0-1.0)
        epss_score (float | None | Unset): EPSS exploitation probability (0.0-1.0)
        has_public_exploit (bool | Unset): Whether a public exploit or PoC is known to exist Default: False.
        modified (None | str | Unset): Last modification date (ISO 8601)
        poc_count (int | Unset): Number of proof-of-concept repositories on GitHub Default: 0.
        published (None | str | Unset): Publication date (ISO 8601)
        references (list[CVEReference] | Unset): Advisory and reference links
        vuln_status (None | str | Unset): NVD record status for this CVE: `Received` / `Awaiting Analysis` / `Undergoing
            Analysis` / `Analyzed` / `Modified` / `Deferred` / `Rejected`. A `Rejected` record is a withdrawn or duplicate
            CVE — without this field it was indistinguishable from a live vulnerability.
        weaponization_score (float | None | Unset): Computed weaponization risk score (0-100)
    """

    cve_id: str
    cna_contact: None | str | Unset = UNSET
    cna_name: None | str | Unset = UNSET
    created_by_ref: None | str | Unset = UNSET
    cvss_alternates: list[CVSSAlternate] | Unset = UNSET
    cvss_v2_entry_type: None | str | Unset = UNSET
    cvss_v2_exploitability_score: float | None | Unset = UNSET
    cvss_v2_impact_score: float | None | Unset = UNSET
    cvss_v2_score: float | None | Unset = UNSET
    cvss_v2_severity: None | str | Unset = UNSET
    cvss_v2_source: None | str | Unset = UNSET
    cvss_v2_vector: None | str | Unset = UNSET
    cvss_v3_entry_type: None | str | Unset = UNSET
    cvss_v3_exploitability_score: float | None | Unset = UNSET
    cvss_v3_impact_score: float | None | Unset = UNSET
    cvss_v3_score: float | None | Unset = UNSET
    cvss_v3_severity: None | str | Unset = UNSET
    cvss_v3_source: None | str | Unset = UNSET
    cvss_v3_vector: None | str | Unset = UNSET
    cvss_v3_version: None | str | Unset = UNSET
    cvss_v4_entry_type: None | str | Unset = UNSET
    cvss_v4_score: float | None | Unset = UNSET
    cvss_v4_severity: None | str | Unset = UNSET
    cvss_v4_source: None | str | Unset = UNSET
    cvss_v4_vector: None | str | Unset = UNSET
    cwe_ids: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    epss_percentile: float | None | Unset = UNSET
    epss_score: float | None | Unset = UNSET
    has_public_exploit: bool | Unset = False
    modified: None | str | Unset = UNSET
    poc_count: int | Unset = 0
    published: None | str | Unset = UNSET
    references: list[CVEReference] | Unset = UNSET
    vuln_status: None | str | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.cvss_alternate import CVSSAlternate  # noqa: PLC0415

        cve_id = self.cve_id

        cna_contact: None | str | Unset
        if isinstance(self.cna_contact, Unset):
            cna_contact = UNSET
        else:
            cna_contact = self.cna_contact

        cna_name: None | str | Unset
        if isinstance(self.cna_name, Unset):
            cna_name = UNSET
        else:
            cna_name = self.cna_name

        created_by_ref: None | str | Unset
        if isinstance(self.created_by_ref, Unset):
            created_by_ref = UNSET
        else:
            created_by_ref = self.created_by_ref

        cvss_alternates: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cvss_alternates, Unset):
            cvss_alternates = []
            for cvss_alternates_item_data in self.cvss_alternates:
                cvss_alternates_item = cvss_alternates_item_data.to_dict()
                cvss_alternates.append(cvss_alternates_item)

        cvss_v2_entry_type: None | str | Unset
        if isinstance(self.cvss_v2_entry_type, Unset):
            cvss_v2_entry_type = UNSET
        else:
            cvss_v2_entry_type = self.cvss_v2_entry_type

        cvss_v2_exploitability_score: float | None | Unset
        if isinstance(self.cvss_v2_exploitability_score, Unset):
            cvss_v2_exploitability_score = UNSET
        else:
            cvss_v2_exploitability_score = self.cvss_v2_exploitability_score

        cvss_v2_impact_score: float | None | Unset
        if isinstance(self.cvss_v2_impact_score, Unset):
            cvss_v2_impact_score = UNSET
        else:
            cvss_v2_impact_score = self.cvss_v2_impact_score

        cvss_v2_score: float | None | Unset
        if isinstance(self.cvss_v2_score, Unset):
            cvss_v2_score = UNSET
        else:
            cvss_v2_score = self.cvss_v2_score

        cvss_v2_severity: None | str | Unset
        if isinstance(self.cvss_v2_severity, Unset):
            cvss_v2_severity = UNSET
        else:
            cvss_v2_severity = self.cvss_v2_severity

        cvss_v2_source: None | str | Unset
        if isinstance(self.cvss_v2_source, Unset):
            cvss_v2_source = UNSET
        else:
            cvss_v2_source = self.cvss_v2_source

        cvss_v2_vector: None | str | Unset
        if isinstance(self.cvss_v2_vector, Unset):
            cvss_v2_vector = UNSET
        else:
            cvss_v2_vector = self.cvss_v2_vector

        cvss_v3_entry_type: None | str | Unset
        if isinstance(self.cvss_v3_entry_type, Unset):
            cvss_v3_entry_type = UNSET
        else:
            cvss_v3_entry_type = self.cvss_v3_entry_type

        cvss_v3_exploitability_score: float | None | Unset
        if isinstance(self.cvss_v3_exploitability_score, Unset):
            cvss_v3_exploitability_score = UNSET
        else:
            cvss_v3_exploitability_score = self.cvss_v3_exploitability_score

        cvss_v3_impact_score: float | None | Unset
        if isinstance(self.cvss_v3_impact_score, Unset):
            cvss_v3_impact_score = UNSET
        else:
            cvss_v3_impact_score = self.cvss_v3_impact_score

        cvss_v3_score: float | None | Unset
        if isinstance(self.cvss_v3_score, Unset):
            cvss_v3_score = UNSET
        else:
            cvss_v3_score = self.cvss_v3_score

        cvss_v3_severity: None | str | Unset
        if isinstance(self.cvss_v3_severity, Unset):
            cvss_v3_severity = UNSET
        else:
            cvss_v3_severity = self.cvss_v3_severity

        cvss_v3_source: None | str | Unset
        if isinstance(self.cvss_v3_source, Unset):
            cvss_v3_source = UNSET
        else:
            cvss_v3_source = self.cvss_v3_source

        cvss_v3_vector: None | str | Unset
        if isinstance(self.cvss_v3_vector, Unset):
            cvss_v3_vector = UNSET
        else:
            cvss_v3_vector = self.cvss_v3_vector

        cvss_v3_version: None | str | Unset
        if isinstance(self.cvss_v3_version, Unset):
            cvss_v3_version = UNSET
        else:
            cvss_v3_version = self.cvss_v3_version

        cvss_v4_entry_type: None | str | Unset
        if isinstance(self.cvss_v4_entry_type, Unset):
            cvss_v4_entry_type = UNSET
        else:
            cvss_v4_entry_type = self.cvss_v4_entry_type

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

        cvss_v4_source: None | str | Unset
        if isinstance(self.cvss_v4_source, Unset):
            cvss_v4_source = UNSET
        else:
            cvss_v4_source = self.cvss_v4_source

        cvss_v4_vector: None | str | Unset
        if isinstance(self.cvss_v4_vector, Unset):
            cvss_v4_vector = UNSET
        else:
            cvss_v4_vector = self.cvss_v4_vector

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        epss_percentile: float | None | Unset
        if isinstance(self.epss_percentile, Unset):
            epss_percentile = UNSET
        else:
            epss_percentile = self.epss_percentile

        epss_score: float | None | Unset
        if isinstance(self.epss_score, Unset):
            epss_score = UNSET
        else:
            epss_score = self.epss_score

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

        vuln_status: None | str | Unset
        if isinstance(self.vuln_status, Unset):
            vuln_status = UNSET
        else:
            vuln_status = self.vuln_status

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
        if cna_contact is not UNSET:
            field_dict["cna_contact"] = cna_contact
        if cna_name is not UNSET:
            field_dict["cna_name"] = cna_name
        if created_by_ref is not UNSET:
            field_dict["created_by_ref"] = created_by_ref
        if cvss_alternates is not UNSET:
            field_dict["cvss_alternates"] = cvss_alternates
        if cvss_v2_entry_type is not UNSET:
            field_dict["cvss_v2_entry_type"] = cvss_v2_entry_type
        if cvss_v2_exploitability_score is not UNSET:
            field_dict["cvss_v2_exploitability_score"] = cvss_v2_exploitability_score
        if cvss_v2_impact_score is not UNSET:
            field_dict["cvss_v2_impact_score"] = cvss_v2_impact_score
        if cvss_v2_score is not UNSET:
            field_dict["cvss_v2_score"] = cvss_v2_score
        if cvss_v2_severity is not UNSET:
            field_dict["cvss_v2_severity"] = cvss_v2_severity
        if cvss_v2_source is not UNSET:
            field_dict["cvss_v2_source"] = cvss_v2_source
        if cvss_v2_vector is not UNSET:
            field_dict["cvss_v2_vector"] = cvss_v2_vector
        if cvss_v3_entry_type is not UNSET:
            field_dict["cvss_v3_entry_type"] = cvss_v3_entry_type
        if cvss_v3_exploitability_score is not UNSET:
            field_dict["cvss_v3_exploitability_score"] = cvss_v3_exploitability_score
        if cvss_v3_impact_score is not UNSET:
            field_dict["cvss_v3_impact_score"] = cvss_v3_impact_score
        if cvss_v3_score is not UNSET:
            field_dict["cvss_v3_score"] = cvss_v3_score
        if cvss_v3_severity is not UNSET:
            field_dict["cvss_v3_severity"] = cvss_v3_severity
        if cvss_v3_source is not UNSET:
            field_dict["cvss_v3_source"] = cvss_v3_source
        if cvss_v3_vector is not UNSET:
            field_dict["cvss_v3_vector"] = cvss_v3_vector
        if cvss_v3_version is not UNSET:
            field_dict["cvss_v3_version"] = cvss_v3_version
        if cvss_v4_entry_type is not UNSET:
            field_dict["cvss_v4_entry_type"] = cvss_v4_entry_type
        if cvss_v4_score is not UNSET:
            field_dict["cvss_v4_score"] = cvss_v4_score
        if cvss_v4_severity is not UNSET:
            field_dict["cvss_v4_severity"] = cvss_v4_severity
        if cvss_v4_source is not UNSET:
            field_dict["cvss_v4_source"] = cvss_v4_source
        if cvss_v4_vector is not UNSET:
            field_dict["cvss_v4_vector"] = cvss_v4_vector
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if description is not UNSET:
            field_dict["description"] = description
        if epss_percentile is not UNSET:
            field_dict["epss_percentile"] = epss_percentile
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
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
        if vuln_status is not UNSET:
            field_dict["vuln_status"] = vuln_status
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cve_reference import CVEReference  # noqa: PLC0415
        from ..models.cvss_alternate import CVSSAlternate  # noqa: PLC0415

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        def _parse_cna_contact(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cna_contact = _parse_cna_contact(d.pop("cna_contact", UNSET))

        def _parse_cna_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cna_name = _parse_cna_name(d.pop("cna_name", UNSET))

        def _parse_created_by_ref(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created_by_ref = _parse_created_by_ref(d.pop("created_by_ref", UNSET))

        _cvss_alternates = d.pop("cvss_alternates", UNSET)
        cvss_alternates: list[CVSSAlternate] | Unset = UNSET
        if _cvss_alternates is not UNSET:
            cvss_alternates = []
            for cvss_alternates_item_data in _cvss_alternates:
                cvss_alternates_item = CVSSAlternate.from_dict(cvss_alternates_item_data)

                cvss_alternates.append(cvss_alternates_item)

        def _parse_cvss_v2_entry_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v2_entry_type = _parse_cvss_v2_entry_type(d.pop("cvss_v2_entry_type", UNSET))

        def _parse_cvss_v2_exploitability_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v2_exploitability_score = _parse_cvss_v2_exploitability_score(d.pop("cvss_v2_exploitability_score", UNSET))

        def _parse_cvss_v2_impact_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v2_impact_score = _parse_cvss_v2_impact_score(d.pop("cvss_v2_impact_score", UNSET))

        def _parse_cvss_v2_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v2_score = _parse_cvss_v2_score(d.pop("cvss_v2_score", UNSET))

        def _parse_cvss_v2_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v2_severity = _parse_cvss_v2_severity(d.pop("cvss_v2_severity", UNSET))

        def _parse_cvss_v2_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v2_source = _parse_cvss_v2_source(d.pop("cvss_v2_source", UNSET))

        def _parse_cvss_v2_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v2_vector = _parse_cvss_v2_vector(d.pop("cvss_v2_vector", UNSET))

        def _parse_cvss_v3_entry_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_entry_type = _parse_cvss_v3_entry_type(d.pop("cvss_v3_entry_type", UNSET))

        def _parse_cvss_v3_exploitability_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v3_exploitability_score = _parse_cvss_v3_exploitability_score(d.pop("cvss_v3_exploitability_score", UNSET))

        def _parse_cvss_v3_impact_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v3_impact_score = _parse_cvss_v3_impact_score(d.pop("cvss_v3_impact_score", UNSET))

        def _parse_cvss_v3_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_v3_score = _parse_cvss_v3_score(d.pop("cvss_v3_score", UNSET))

        def _parse_cvss_v3_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_severity = _parse_cvss_v3_severity(d.pop("cvss_v3_severity", UNSET))

        def _parse_cvss_v3_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_source = _parse_cvss_v3_source(d.pop("cvss_v3_source", UNSET))

        def _parse_cvss_v3_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_vector = _parse_cvss_v3_vector(d.pop("cvss_v3_vector", UNSET))

        def _parse_cvss_v3_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v3_version = _parse_cvss_v3_version(d.pop("cvss_v3_version", UNSET))

        def _parse_cvss_v4_entry_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_entry_type = _parse_cvss_v4_entry_type(d.pop("cvss_v4_entry_type", UNSET))

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

        def _parse_cvss_v4_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_source = _parse_cvss_v4_source(d.pop("cvss_v4_source", UNSET))

        def _parse_cvss_v4_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_v4_vector = _parse_cvss_v4_vector(d.pop("cvss_v4_vector", UNSET))

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_epss_percentile(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_percentile = _parse_epss_percentile(d.pop("epss_percentile", UNSET))

        def _parse_epss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_score = _parse_epss_score(d.pop("epss_score", UNSET))

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

        def _parse_vuln_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vuln_status = _parse_vuln_status(d.pop("vuln_status", UNSET))

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        cve_detail = cls(
            cve_id=cve_id,
            cna_contact=cna_contact,
            cna_name=cna_name,
            created_by_ref=created_by_ref,
            cvss_alternates=cvss_alternates,
            cvss_v2_entry_type=cvss_v2_entry_type,
            cvss_v2_exploitability_score=cvss_v2_exploitability_score,
            cvss_v2_impact_score=cvss_v2_impact_score,
            cvss_v2_score=cvss_v2_score,
            cvss_v2_severity=cvss_v2_severity,
            cvss_v2_source=cvss_v2_source,
            cvss_v2_vector=cvss_v2_vector,
            cvss_v3_entry_type=cvss_v3_entry_type,
            cvss_v3_exploitability_score=cvss_v3_exploitability_score,
            cvss_v3_impact_score=cvss_v3_impact_score,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_severity=cvss_v3_severity,
            cvss_v3_source=cvss_v3_source,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v3_version=cvss_v3_version,
            cvss_v4_entry_type=cvss_v4_entry_type,
            cvss_v4_score=cvss_v4_score,
            cvss_v4_severity=cvss_v4_severity,
            cvss_v4_source=cvss_v4_source,
            cvss_v4_vector=cvss_v4_vector,
            cwe_ids=cwe_ids,
            description=description,
            epss_percentile=epss_percentile,
            epss_score=epss_score,
            has_public_exploit=has_public_exploit,
            modified=modified,
            poc_count=poc_count,
            published=published,
            references=references,
            vuln_status=vuln_status,
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
