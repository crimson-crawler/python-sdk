from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.similar_cve_mini_signal_breakdown import SimilarCVEMiniSignalBreakdown


T = TypeVar("T", bound="SimilarCVEMini")


@_attrs_define
class SimilarCVEMini:
    """A candidate CVE from the similarity ranking (`EnrichCVEResponse.similar_cves`).

    Each row is scored against the response's own CVE, so every field below is populated on every
    row. Kept separate from `CVEMiniDetail` so the other `cves[]` lists — which are joined, never
    ranked — do not advertise a score they cannot compute.

        Attributes:
            cve_id (str): CVE identifier
            similarity_score (float): Weighted Jaccard similarity to the source CVE (0.0-1.0), ranking key
            cvss_v2_entry_type (None | str | Unset): NVD's Primary/Secondary discriminator for the surfaced CVSS v2.x entry
            cvss_v2_exploitability_score (float | None | Unset): CVSS v2.0 exploitability sub-score (0.0-10.0)
            cvss_v2_impact_score (float | None | Unset): CVSS v2.0 impact sub-score (0.0-10.0)
            cvss_v2_score (float | None | Unset): CVSS v2.0 base score (0.0-10.0)
            cvss_v2_severity (None | str | Unset): CVSS v2.0 severity: LOW, MEDIUM, HIGH
            cvss_v2_source (None | str | Unset): Who scored this CVE under CVSS v2.0
            cvss_v3_entry_type (None | str | Unset): NVD's Primary/Secondary discriminator for the surfaced CVSS v3.x entry
            cvss_v3_exploitability_score (float | None | Unset): CVSS v3.x exploitability sub-score (0.0-10.0)
            cvss_v3_impact_score (float | None | Unset): CVSS v3.x impact sub-score (0.0-10.0)
            cvss_v3_score (float | None | Unset): CVSS v3.x base score (0.0-10.0)
            cvss_v3_severity (None | str | Unset): CVSS v3.x severity: NONE, LOW, MEDIUM, HIGH, CRITICAL
            cvss_v3_source (None | str | Unset): Who scored this CVE under CVSS v3.x
            cvss_v3_version (None | str | Unset): Which v3 revision the `cvss_v3_*` fields hold — '3.1' or '3.0'
            cvss_v4_entry_type (None | str | Unset): NVD's Primary/Secondary discriminator for the surfaced CVSS v4.x entry
            cvss_v4_score (float | None | Unset): CVSS v4.0 base score (0.0-10.0)
            cvss_v4_severity (None | str | Unset): CVSS v4.0 severity: NONE, LOW, MEDIUM, HIGH, CRITICAL
            cvss_v4_source (None | str | Unset): Who scored this CVE under CVSS v4.0
            description (None | str | Unset): Brief description
            epss_score (float | None | Unset): EPSS exploitation probability
            in_kev (bool | Unset): In the Known Exploited Vulnerabilities catalog Default: False.
            poc_count (int | Unset): Number of PoC repositories on GitHub Default: 0.
            shared_cwes (list[str] | Unset): CWE IDs shared with the source CVE
            shared_techniques (list[str] | Unset): Technique IDs shared with the source CVE
            signal_breakdown (SimilarCVEMiniSignalBreakdown | Unset): Per-signal contribution to `similarity_score`:
                `jaccard_technique` (×0.50), `jaccard_cwe` (×0.30), `jaccard_capec` (materialised from tactic overlap, ×0.20),
                `cpe_overlap` (+0.15 when a vendor:product matches) and `cvss_distance` (≤+0.10, from the AV/AC/PR/UI Hamming
                similarity)
            weaponization_score (float | None | Unset): Computed risk score (0-100)
    """

    cve_id: str
    similarity_score: float
    cvss_v2_entry_type: None | str | Unset = UNSET
    cvss_v2_exploitability_score: float | None | Unset = UNSET
    cvss_v2_impact_score: float | None | Unset = UNSET
    cvss_v2_score: float | None | Unset = UNSET
    cvss_v2_severity: None | str | Unset = UNSET
    cvss_v2_source: None | str | Unset = UNSET
    cvss_v3_entry_type: None | str | Unset = UNSET
    cvss_v3_exploitability_score: float | None | Unset = UNSET
    cvss_v3_impact_score: float | None | Unset = UNSET
    cvss_v3_score: float | None | Unset = UNSET
    cvss_v3_severity: None | str | Unset = UNSET
    cvss_v3_source: None | str | Unset = UNSET
    cvss_v3_version: None | str | Unset = UNSET
    cvss_v4_entry_type: None | str | Unset = UNSET
    cvss_v4_score: float | None | Unset = UNSET
    cvss_v4_severity: None | str | Unset = UNSET
    cvss_v4_source: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    epss_score: float | None | Unset = UNSET
    in_kev: bool | Unset = False
    poc_count: int | Unset = 0
    shared_cwes: list[str] | Unset = UNSET
    shared_techniques: list[str] | Unset = UNSET
    signal_breakdown: SimilarCVEMiniSignalBreakdown | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.similar_cve_mini_signal_breakdown import SimilarCVEMiniSignalBreakdown  # noqa: PLC0415

        cve_id = self.cve_id

        similarity_score = self.similarity_score

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

        signal_breakdown: dict[str, Any] | Unset = UNSET
        if not isinstance(self.signal_breakdown, Unset):
            signal_breakdown = self.signal_breakdown.to_dict()

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
                "similarity_score": similarity_score,
            }
        )
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
        if signal_breakdown is not UNSET:
            field_dict["signal_breakdown"] = signal_breakdown
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.similar_cve_mini_signal_breakdown import SimilarCVEMiniSignalBreakdown  # noqa: PLC0415

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        similarity_score = d.pop("similarity_score")

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

        _signal_breakdown = d.pop("signal_breakdown", UNSET)
        signal_breakdown: SimilarCVEMiniSignalBreakdown | Unset
        if isinstance(_signal_breakdown, Unset):
            signal_breakdown = UNSET
        else:
            signal_breakdown = SimilarCVEMiniSignalBreakdown.from_dict(_signal_breakdown)

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        similar_cve_mini = cls(
            cve_id=cve_id,
            similarity_score=similarity_score,
            cvss_v2_entry_type=cvss_v2_entry_type,
            cvss_v2_exploitability_score=cvss_v2_exploitability_score,
            cvss_v2_impact_score=cvss_v2_impact_score,
            cvss_v2_score=cvss_v2_score,
            cvss_v2_severity=cvss_v2_severity,
            cvss_v2_source=cvss_v2_source,
            cvss_v3_entry_type=cvss_v3_entry_type,
            cvss_v3_exploitability_score=cvss_v3_exploitability_score,
            cvss_v3_impact_score=cvss_v3_impact_score,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_severity=cvss_v3_severity,
            cvss_v3_source=cvss_v3_source,
            cvss_v3_version=cvss_v3_version,
            cvss_v4_entry_type=cvss_v4_entry_type,
            cvss_v4_score=cvss_v4_score,
            cvss_v4_severity=cvss_v4_severity,
            cvss_v4_source=cvss_v4_source,
            description=description,
            epss_score=epss_score,
            in_kev=in_kev,
            poc_count=poc_count,
            shared_cwes=shared_cwes,
            shared_techniques=shared_techniques,
            signal_breakdown=signal_breakdown,
            weaponization_score=weaponization_score,
        )

        similar_cve_mini.additional_properties = d
        return similar_cve_mini

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
