from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="NucleiTemplate")


@_attrs_define
class NucleiTemplate:
    """One ProjectDiscovery Nuclei template whose own id/classification names the CVE.

    Only the template's published header fields are projected — no request, flow, or network block
    is ever parsed or published. Fields a template does not declare are ABSENT rather than defaulted.

        Attributes:
            attribution (str | Unset): Upstream copyright notice Default: 'Copyright 2025 ProjectDiscovery, Inc.'.
            author (None | str | Unset): Template author(s)
            cve_ids (list[str] | Unset): CVE ids the template classifies itself against
            cvss_metrics (None | str | Unset): CVSS vector the template declares
            cvss_score (float | None | Unset): CVSS score the template declares
            cwe_ids (list[str] | Unset): CWE ids the template classifies itself against
            description (None | str | Unset): Template description
            epss_percentile (float | None | Unset): EPSS percentile the template carries at publish time
            epss_score (float | None | Unset): EPSS score the template carries at publish time
            id (str | Unset): Template id Default: ''.
            impact (None | str | Unset): Template's stated impact
            licence (str | Unset): Licence for the template metadata Default: 'MIT'.
            licence_url (str | Unset): Licence text Default: 'https://github.com/projectdiscovery/nuclei-
                templates/blob/main/LICENSE.md'.
            max_request (int | None | Unset): `max-request` the template declares
            name (None | str | Unset): Template name
            ot_protocols (list[str] | Unset): Curated OT protocol ids named by the template's tags, id, name or path (e.g.
                `modbus`, `dnp3`, `s7comm`). Empty when the template names no curated protocol.
            path (str | Unset): In-repo template path Default: ''.
            product (None | str | Unset): Product the template names
            reference (list[str] | Unset): Template reference URLs
            remediation (None | str | Unset): Template's stated remediation
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            severity (None | str | Unset): Template severity (info → critical)
            source (str | Unset): Provenance label Default: 'nuclei_templates'.
            source_url (str | Unset): URL the template header was read from Default: ''.
            tags (list[str] | Unset): Template tags
            vendor (None | str | Unset): Vendor the template names
            verified (bool | None | Unset): Whether the source marks the template verified
    """

    attribution: str | Unset = "Copyright 2025 ProjectDiscovery, Inc."
    author: None | str | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    cvss_metrics: None | str | Unset = UNSET
    cvss_score: float | None | Unset = UNSET
    cwe_ids: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    epss_percentile: float | None | Unset = UNSET
    epss_score: float | None | Unset = UNSET
    id: str | Unset = ""
    impact: None | str | Unset = UNSET
    licence: str | Unset = "MIT"
    licence_url: str | Unset = "https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md"
    max_request: int | None | Unset = UNSET
    name: None | str | Unset = UNSET
    ot_protocols: list[str] | Unset = UNSET
    path: str | Unset = ""
    product: None | str | Unset = UNSET
    reference: list[str] | Unset = UNSET
    remediation: None | str | Unset = UNSET
    retrieved_at: str | Unset = ""
    severity: None | str | Unset = UNSET
    source: str | Unset = "nuclei_templates"
    source_url: str | Unset = ""
    tags: list[str] | Unset = UNSET
    vendor: None | str | Unset = UNSET
    verified: bool | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attribution = self.attribution

        author: None | str | Unset
        if isinstance(self.author, Unset):
            author = UNSET
        else:
            author = self.author

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        cvss_metrics: None | str | Unset
        if isinstance(self.cvss_metrics, Unset):
            cvss_metrics = UNSET
        else:
            cvss_metrics = self.cvss_metrics

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

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

        id = self.id

        impact: None | str | Unset
        if isinstance(self.impact, Unset):
            impact = UNSET
        else:
            impact = self.impact

        licence = self.licence

        licence_url = self.licence_url

        max_request: int | None | Unset
        if isinstance(self.max_request, Unset):
            max_request = UNSET
        else:
            max_request = self.max_request

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        ot_protocols: list[str] | Unset = UNSET
        if not isinstance(self.ot_protocols, Unset):
            ot_protocols = self.ot_protocols

        path = self.path

        product: None | str | Unset
        if isinstance(self.product, Unset):
            product = UNSET
        else:
            product = self.product

        reference: list[str] | Unset = UNSET
        if not isinstance(self.reference, Unset):
            reference = self.reference

        remediation: None | str | Unset
        if isinstance(self.remediation, Unset):
            remediation = UNSET
        else:
            remediation = self.remediation

        retrieved_at = self.retrieved_at

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        source = self.source

        source_url = self.source_url

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        verified: bool | None | Unset
        if isinstance(self.verified, Unset):
            verified = UNSET
        else:
            verified = self.verified

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if author is not UNSET:
            field_dict["author"] = author
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if cvss_metrics is not UNSET:
            field_dict["cvss_metrics"] = cvss_metrics
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if description is not UNSET:
            field_dict["description"] = description
        if epss_percentile is not UNSET:
            field_dict["epss_percentile"] = epss_percentile
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if id is not UNSET:
            field_dict["id"] = id
        if impact is not UNSET:
            field_dict["impact"] = impact
        if licence is not UNSET:
            field_dict["licence"] = licence
        if licence_url is not UNSET:
            field_dict["licence_url"] = licence_url
        if max_request is not UNSET:
            field_dict["max_request"] = max_request
        if name is not UNSET:
            field_dict["name"] = name
        if ot_protocols is not UNSET:
            field_dict["ot_protocols"] = ot_protocols
        if path is not UNSET:
            field_dict["path"] = path
        if product is not UNSET:
            field_dict["product"] = product
        if reference is not UNSET:
            field_dict["reference"] = reference
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if severity is not UNSET:
            field_dict["severity"] = severity
        if source is not UNSET:
            field_dict["source"] = source
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if tags is not UNSET:
            field_dict["tags"] = tags
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if verified is not UNSET:
            field_dict["verified"] = verified

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        attribution = d.pop("attribution", UNSET)

        def _parse_author(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        author = _parse_author(d.pop("author", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_cvss_metrics(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_metrics = _parse_cvss_metrics(d.pop("cvss_metrics", UNSET))

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

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

        id = d.pop("id", UNSET)

        def _parse_impact(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        impact = _parse_impact(d.pop("impact", UNSET))

        licence = d.pop("licence", UNSET)

        licence_url = d.pop("licence_url", UNSET)

        def _parse_max_request(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        max_request = _parse_max_request(d.pop("max_request", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        ot_protocols = cast(list[str], d.pop("ot_protocols", UNSET))

        path = d.pop("path", UNSET)

        def _parse_product(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product = _parse_product(d.pop("product", UNSET))

        reference = cast(list[str], d.pop("reference", UNSET))

        def _parse_remediation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation = _parse_remediation(d.pop("remediation", UNSET))

        retrieved_at = d.pop("retrieved_at", UNSET)

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        def _parse_verified(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        verified = _parse_verified(d.pop("verified", UNSET))

        nuclei_template = cls(
            attribution=attribution,
            author=author,
            cve_ids=cve_ids,
            cvss_metrics=cvss_metrics,
            cvss_score=cvss_score,
            cwe_ids=cwe_ids,
            description=description,
            epss_percentile=epss_percentile,
            epss_score=epss_score,
            id=id,
            impact=impact,
            licence=licence,
            licence_url=licence_url,
            max_request=max_request,
            name=name,
            ot_protocols=ot_protocols,
            path=path,
            product=product,
            reference=reference,
            remediation=remediation,
            retrieved_at=retrieved_at,
            severity=severity,
            source=source,
            source_url=source_url,
            tags=tags,
            vendor=vendor,
            verified=verified,
        )

        nuclei_template.additional_properties = d
        return nuclei_template

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
