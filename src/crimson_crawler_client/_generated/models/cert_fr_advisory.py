from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CertFRAdvisory")


@_attrs_define
class CertFRAdvisory:
    """One CERT-FR (ANSSI) advisory or alert that references a CVE.

    Link and metadata only — the advisory body is never redistributed.

        Attributes:
            id (str): CERT-FR reference (CERTFR-YYYY-AVI-NNNN or CERTFR-YYYY-ALE-NNN)
            source_url (str): The list endpoint the row came from
            title (str): Advisory title as published (French, unchanged)
            url (str): Canonical CERT-FR advisory page
            cve_ids (list[str] | Unset): CVE ids the advisory's own `cves` entries name — the index key. Never empty on a
                row.
            date (None | str | Unset): Last revision date as an ISO-8601 calendar date (YYYY-MM-DD)
            products (list[str] | Unset): Product names from `affected_systems`
            risks (list[str] | Unset): Risk descriptions as published (facts only; the advisory content body is never
                redistributed)
            scada (bool | Unset): The advisory's own SCADA/ICS flag: the list-level `scada` boolean for avis, and (for
                alertes, which publish no list-level flag) true when any affected system's vendor is flagged `scada`. Default:
                False.
            source (str | Unset): Stable source label Default: 'certfr'.
            vendors (list[str] | Unset): Vendor names from `affected_systems`
    """

    id: str
    source_url: str
    title: str
    url: str
    cve_ids: list[str] | Unset = UNSET
    date: None | str | Unset = UNSET
    products: list[str] | Unset = UNSET
    risks: list[str] | Unset = UNSET
    scada: bool | Unset = False
    source: str | Unset = "certfr"
    vendors: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        source_url = self.source_url

        title = self.title

        url = self.url

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        date: None | str | Unset
        if isinstance(self.date, Unset):
            date = UNSET
        else:
            date = self.date

        products: list[str] | Unset = UNSET
        if not isinstance(self.products, Unset):
            products = self.products

        risks: list[str] | Unset = UNSET
        if not isinstance(self.risks, Unset):
            risks = self.risks

        scada = self.scada

        source = self.source

        vendors: list[str] | Unset = UNSET
        if not isinstance(self.vendors, Unset):
            vendors = self.vendors

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "source_url": source_url,
                "title": title,
                "url": url,
            }
        )
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if date is not UNSET:
            field_dict["date"] = date
        if products is not UNSET:
            field_dict["products"] = products
        if risks is not UNSET:
            field_dict["risks"] = risks
        if scada is not UNSET:
            field_dict["scada"] = scada
        if source is not UNSET:
            field_dict["source"] = source
        if vendors is not UNSET:
            field_dict["vendors"] = vendors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        source_url = d.pop("source_url")

        title = d.pop("title")

        url = d.pop("url")

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date = _parse_date(d.pop("date", UNSET))

        products = cast(list[str], d.pop("products", UNSET))

        risks = cast(list[str], d.pop("risks", UNSET))

        scada = d.pop("scada", UNSET)

        source = d.pop("source", UNSET)

        vendors = cast(list[str], d.pop("vendors", UNSET))

        cert_fr_advisory = cls(
            id=id,
            source_url=source_url,
            title=title,
            url=url,
            cve_ids=cve_ids,
            date=date,
            products=products,
            risks=risks,
            scada=scada,
            source=source,
            vendors=vendors,
        )

        cert_fr_advisory.additional_properties = d
        return cert_fr_advisory

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
