from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.ot_vendor_advisory_source import OTVendorAdvisorySource
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ot_vendor_advisory_cvss import OTVendorAdvisoryCVSS


T = TypeVar("T", bound="OTVendorAdvisory")


@_attrs_define
class OTVendorAdvisory:
    """One direct OT/embedded vendor advisory that references a CVE.

    Two keyless vendors share this row shape: Rockwell Automation (`rockwell`, SD-series
    advisories from its security RSS) and MediaTek (`mediatek`, monthly product-security
    bulletins). Link and metadata only — no advisory body is redistributed. The seeded corpus
    is refreshed by ``scripts/seed-data.sh``; reads are in-process and cost no upstream call.

        Attributes:
            advisory_id (str): The vendor's own advisory id (SD1801, 8DBD000254, or the bulletin month)
            source (OTVendorAdvisorySource): Which vendor produced the row: rockwell or mediatek
            source_url (str): The feed/page the row was read from
            url (str): Canonical advisory URL (per-CVE anchor for a MediaTek bulletin)
            chipsets (list[str] | Unset): Affected MediaTek chipset model codes (MT####)
            cve_ids (list[str] | Unset): Every CVE the advisory names
            cvss (list[OTVendorAdvisoryCVSS] | Unset): Per-CVE CVSS scores the advisory publishes (Rockwell v3.1/v4.0)
            cwe (list[str] | Unset): CWE ids the advisory names
            exploited (bool | None | Unset): Whether the vendor marks a CVE as exploited in the wild
            products (list[str] | Unset): Product names/tags the advisory names
            published (None | str | Unset): Publication date in ISO-8601. Rockwell publishes a timestamp (e.g.
                `2026-10-13T12:35:00+00:00`) and MediaTek only a month — its value is that month's first day (`2026-10-01`).
            severity (None | str | Unset): Severity label the vendor publishes (MediaTek)
            subcomponent (None | str | Unset): MediaTek subcomponent (Modem, aidl, …)
            title (None | str | Unset): Advisory title as the vendor publishes it
            updated (None | str | Unset): Last update date in ISO-8601, same precision rules as `published`
    """

    advisory_id: str
    source: OTVendorAdvisorySource
    source_url: str
    url: str
    chipsets: list[str] | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    cvss: list[OTVendorAdvisoryCVSS] | Unset = UNSET
    cwe: list[str] | Unset = UNSET
    exploited: bool | None | Unset = UNSET
    products: list[str] | Unset = UNSET
    published: None | str | Unset = UNSET
    severity: None | str | Unset = UNSET
    subcomponent: None | str | Unset = UNSET
    title: None | str | Unset = UNSET
    updated: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.ot_vendor_advisory_cvss import OTVendorAdvisoryCVSS  # noqa: PLC0415

        advisory_id = self.advisory_id

        source = self.source.value

        source_url = self.source_url

        url = self.url

        chipsets: list[str] | Unset = UNSET
        if not isinstance(self.chipsets, Unset):
            chipsets = self.chipsets

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        cvss: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cvss, Unset):
            cvss = []
            for cvss_item_data in self.cvss:
                cvss_item = cvss_item_data.to_dict()
                cvss.append(cvss_item)

        cwe: list[str] | Unset = UNSET
        if not isinstance(self.cwe, Unset):
            cwe = self.cwe

        exploited: bool | None | Unset
        if isinstance(self.exploited, Unset):
            exploited = UNSET
        else:
            exploited = self.exploited

        products: list[str] | Unset = UNSET
        if not isinstance(self.products, Unset):
            products = self.products

        published: None | str | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        subcomponent: None | str | Unset
        if isinstance(self.subcomponent, Unset):
            subcomponent = UNSET
        else:
            subcomponent = self.subcomponent

        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        updated: None | str | Unset
        if isinstance(self.updated, Unset):
            updated = UNSET
        else:
            updated = self.updated

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "advisory_id": advisory_id,
                "source": source,
                "source_url": source_url,
                "url": url,
            }
        )
        if chipsets is not UNSET:
            field_dict["chipsets"] = chipsets
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if cvss is not UNSET:
            field_dict["cvss"] = cvss
        if cwe is not UNSET:
            field_dict["cwe"] = cwe
        if exploited is not UNSET:
            field_dict["exploited"] = exploited
        if products is not UNSET:
            field_dict["products"] = products
        if published is not UNSET:
            field_dict["published"] = published
        if severity is not UNSET:
            field_dict["severity"] = severity
        if subcomponent is not UNSET:
            field_dict["subcomponent"] = subcomponent
        if title is not UNSET:
            field_dict["title"] = title
        if updated is not UNSET:
            field_dict["updated"] = updated

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ot_vendor_advisory_cvss import OTVendorAdvisoryCVSS  # noqa: PLC0415

        d = dict(src_dict)
        advisory_id = d.pop("advisory_id")

        source = OTVendorAdvisorySource(d.pop("source"))

        source_url = d.pop("source_url")

        url = d.pop("url")

        chipsets = cast(list[str], d.pop("chipsets", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        _cvss = d.pop("cvss", UNSET)
        cvss: list[OTVendorAdvisoryCVSS] | Unset = UNSET
        if _cvss is not UNSET:
            cvss = []
            for cvss_item_data in _cvss:
                cvss_item = OTVendorAdvisoryCVSS.from_dict(cvss_item_data)

                cvss.append(cvss_item)

        cwe = cast(list[str], d.pop("cwe", UNSET))

        def _parse_exploited(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        exploited = _parse_exploited(d.pop("exploited", UNSET))

        products = cast(list[str], d.pop("products", UNSET))

        def _parse_published(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        def _parse_subcomponent(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        subcomponent = _parse_subcomponent(d.pop("subcomponent", UNSET))

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        def _parse_updated(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        updated = _parse_updated(d.pop("updated", UNSET))

        ot_vendor_advisory = cls(
            advisory_id=advisory_id,
            source=source,
            source_url=source_url,
            url=url,
            chipsets=chipsets,
            cve_ids=cve_ids,
            cvss=cvss,
            cwe=cwe,
            exploited=exploited,
            products=products,
            published=published,
            severity=severity,
            subcomponent=subcomponent,
            title=title,
            updated=updated,
        )

        ot_vendor_advisory.additional_properties = d
        return ot_vendor_advisory

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
