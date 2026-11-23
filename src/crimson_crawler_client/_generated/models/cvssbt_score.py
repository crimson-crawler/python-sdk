from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CVSSBTScore")


@_attrs_define
class CVSSBTScore:
    """One cvss-bt corpus row: the Base+Threat composite plus the exploit flags it publishes.

    Never feeds `weaponization_score` or `has_public_exploit` — the same invariant the
    Metasploit and Nuclei layers hold; a corpus read must not move an existing verdict.

        Attributes:
            cve_id (str): CVE the row scores
            source_url (str): The corpus file's upstream URL
            cvss_bt_base (float | None | Unset): CVSS base score
            cvss_bt_severity (None | str | Unset): Severity of the Base+Threat score
            cvss_bt_threat (float | None | Unset): CVSS Base+Threat composite score
            dataset_modified (None | str | Unset): When the corpus file was last modified
            exploitdb (bool | Unset): ExploitDB evidence the corpus publishes Default: False.
            metasploit (bool | Unset): Metasploit evidence the corpus publishes Default: False.
            nuclei (bool | Unset): Nuclei evidence the corpus publishes Default: False.
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            source (str | Unset): Stable source label Default: 'cvss-bt'.
            vulncheck_kev (bool | Unset): VulnCheck KEV membership the corpus publishes Default: False.
    """

    cve_id: str
    source_url: str
    cvss_bt_base: float | None | Unset = UNSET
    cvss_bt_severity: None | str | Unset = UNSET
    cvss_bt_threat: float | None | Unset = UNSET
    dataset_modified: None | str | Unset = UNSET
    exploitdb: bool | Unset = False
    metasploit: bool | Unset = False
    nuclei: bool | Unset = False
    retrieved_at: str | Unset = ""
    source: str | Unset = "cvss-bt"
    vulncheck_kev: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        source_url = self.source_url

        cvss_bt_base: float | None | Unset
        if isinstance(self.cvss_bt_base, Unset):
            cvss_bt_base = UNSET
        else:
            cvss_bt_base = self.cvss_bt_base

        cvss_bt_severity: None | str | Unset
        if isinstance(self.cvss_bt_severity, Unset):
            cvss_bt_severity = UNSET
        else:
            cvss_bt_severity = self.cvss_bt_severity

        cvss_bt_threat: float | None | Unset
        if isinstance(self.cvss_bt_threat, Unset):
            cvss_bt_threat = UNSET
        else:
            cvss_bt_threat = self.cvss_bt_threat

        dataset_modified: None | str | Unset
        if isinstance(self.dataset_modified, Unset):
            dataset_modified = UNSET
        else:
            dataset_modified = self.dataset_modified

        exploitdb = self.exploitdb

        metasploit = self.metasploit

        nuclei = self.nuclei

        retrieved_at = self.retrieved_at

        source = self.source

        vulncheck_kev = self.vulncheck_kev

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "source_url": source_url,
            }
        )
        if cvss_bt_base is not UNSET:
            field_dict["cvss_bt_base"] = cvss_bt_base
        if cvss_bt_severity is not UNSET:
            field_dict["cvss_bt_severity"] = cvss_bt_severity
        if cvss_bt_threat is not UNSET:
            field_dict["cvss_bt_threat"] = cvss_bt_threat
        if dataset_modified is not UNSET:
            field_dict["dataset_modified"] = dataset_modified
        if exploitdb is not UNSET:
            field_dict["exploitdb"] = exploitdb
        if metasploit is not UNSET:
            field_dict["metasploit"] = metasploit
        if nuclei is not UNSET:
            field_dict["nuclei"] = nuclei
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if source is not UNSET:
            field_dict["source"] = source
        if vulncheck_kev is not UNSET:
            field_dict["vulncheck_kev"] = vulncheck_kev

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        source_url = d.pop("source_url")

        def _parse_cvss_bt_base(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_bt_base = _parse_cvss_bt_base(d.pop("cvss_bt_base", UNSET))

        def _parse_cvss_bt_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_bt_severity = _parse_cvss_bt_severity(d.pop("cvss_bt_severity", UNSET))

        def _parse_cvss_bt_threat(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_bt_threat = _parse_cvss_bt_threat(d.pop("cvss_bt_threat", UNSET))

        def _parse_dataset_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dataset_modified = _parse_dataset_modified(d.pop("dataset_modified", UNSET))

        exploitdb = d.pop("exploitdb", UNSET)

        metasploit = d.pop("metasploit", UNSET)

        nuclei = d.pop("nuclei", UNSET)

        retrieved_at = d.pop("retrieved_at", UNSET)

        source = d.pop("source", UNSET)

        vulncheck_kev = d.pop("vulncheck_kev", UNSET)

        cvssbt_score = cls(
            cve_id=cve_id,
            source_url=source_url,
            cvss_bt_base=cvss_bt_base,
            cvss_bt_severity=cvss_bt_severity,
            cvss_bt_threat=cvss_bt_threat,
            dataset_modified=dataset_modified,
            exploitdb=exploitdb,
            metasploit=metasploit,
            nuclei=nuclei,
            retrieved_at=retrieved_at,
            source=source,
            vulncheck_kev=vulncheck_kev,
        )

        cvssbt_score.additional_properties = d
        return cvssbt_score

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
