from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KEVEntry")


@_attrs_define
class KEVEntry:
    """Known Exploited Vulnerabilities catalog entry - confirmed active exploitation in the wild.

    Attributes:
        cve_id (str): CVE identifier
        date_added (None | str | Unset): Date added to the KEV catalog
        description (None | str | Unset): Brief description of the vulnerability
        due_date (None | str | Unset): Required remediation deadline
        epss_percentile (float | None | Unset): EPSS percentile rank among all scored CVEs (0.0-1.0)
        epss_score (float | None | Unset): EPSS exploitation probability (0.0-1.0)
        in_kev (bool | Unset): Whether this CVE is in the Known Exploited Vulnerabilities catalog Default: True.
        name (None | str | Unset): Vulnerability name
        notes (None | str | Unset): Additional remediation notes
        poc_count (int | Unset): Number of proof-of-concept repositories on GitHub Default: 0.
        product (None | str | Unset): Affected product name
        ransomware (bool | Unset): Whether this CVE is known to be used in ransomware campaigns Default: False.
        required_action (None | str | Unset): CISA KEV requiredAction (BOD 22-01 remediation)
        short_description (None | str | Unset): CISA KEV shortDescription
        vendor_project (None | str | Unset): CISA KEV vendorProject (the affected vendor)
        vulnerability_name (None | str | Unset): CISA KEV vulnerabilityName (the catalog title)
        weaponization_score (float | None | Unset): Computed weaponization risk score (0-100)
    """

    cve_id: str
    date_added: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    due_date: None | str | Unset = UNSET
    epss_percentile: float | None | Unset = UNSET
    epss_score: float | None | Unset = UNSET
    in_kev: bool | Unset = True
    name: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    poc_count: int | Unset = 0
    product: None | str | Unset = UNSET
    ransomware: bool | Unset = False
    required_action: None | str | Unset = UNSET
    short_description: None | str | Unset = UNSET
    vendor_project: None | str | Unset = UNSET
    vulnerability_name: None | str | Unset = UNSET
    weaponization_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        date_added: None | str | Unset
        if isinstance(self.date_added, Unset):
            date_added = UNSET
        else:
            date_added = self.date_added

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        due_date: None | str | Unset
        if isinstance(self.due_date, Unset):
            due_date = UNSET
        else:
            due_date = self.due_date

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

        in_kev = self.in_kev

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        poc_count = self.poc_count

        product: None | str | Unset
        if isinstance(self.product, Unset):
            product = UNSET
        else:
            product = self.product

        ransomware = self.ransomware

        required_action: None | str | Unset
        if isinstance(self.required_action, Unset):
            required_action = UNSET
        else:
            required_action = self.required_action

        short_description: None | str | Unset
        if isinstance(self.short_description, Unset):
            short_description = UNSET
        else:
            short_description = self.short_description

        vendor_project: None | str | Unset
        if isinstance(self.vendor_project, Unset):
            vendor_project = UNSET
        else:
            vendor_project = self.vendor_project

        vulnerability_name: None | str | Unset
        if isinstance(self.vulnerability_name, Unset):
            vulnerability_name = UNSET
        else:
            vulnerability_name = self.vulnerability_name

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
        if date_added is not UNSET:
            field_dict["date_added"] = date_added
        if description is not UNSET:
            field_dict["description"] = description
        if due_date is not UNSET:
            field_dict["due_date"] = due_date
        if epss_percentile is not UNSET:
            field_dict["epss_percentile"] = epss_percentile
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if in_kev is not UNSET:
            field_dict["in_kev"] = in_kev
        if name is not UNSET:
            field_dict["name"] = name
        if notes is not UNSET:
            field_dict["notes"] = notes
        if poc_count is not UNSET:
            field_dict["poc_count"] = poc_count
        if product is not UNSET:
            field_dict["product"] = product
        if ransomware is not UNSET:
            field_dict["ransomware"] = ransomware
        if required_action is not UNSET:
            field_dict["required_action"] = required_action
        if short_description is not UNSET:
            field_dict["short_description"] = short_description
        if vendor_project is not UNSET:
            field_dict["vendor_project"] = vendor_project
        if vulnerability_name is not UNSET:
            field_dict["vulnerability_name"] = vulnerability_name
        if weaponization_score is not UNSET:
            field_dict["weaponization_score"] = weaponization_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        def _parse_date_added(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date_added = _parse_date_added(d.pop("date_added", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_due_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        due_date = _parse_due_date(d.pop("due_date", UNSET))

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

        in_kev = d.pop("in_kev", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        poc_count = d.pop("poc_count", UNSET)

        def _parse_product(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product = _parse_product(d.pop("product", UNSET))

        ransomware = d.pop("ransomware", UNSET)

        def _parse_required_action(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        required_action = _parse_required_action(d.pop("required_action", UNSET))

        def _parse_short_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        short_description = _parse_short_description(d.pop("short_description", UNSET))

        def _parse_vendor_project(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor_project = _parse_vendor_project(d.pop("vendor_project", UNSET))

        def _parse_vulnerability_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vulnerability_name = _parse_vulnerability_name(d.pop("vulnerability_name", UNSET))

        def _parse_weaponization_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        weaponization_score = _parse_weaponization_score(d.pop("weaponization_score", UNSET))

        kev_entry = cls(
            cve_id=cve_id,
            date_added=date_added,
            description=description,
            due_date=due_date,
            epss_percentile=epss_percentile,
            epss_score=epss_score,
            in_kev=in_kev,
            name=name,
            notes=notes,
            poc_count=poc_count,
            product=product,
            ransomware=ransomware,
            required_action=required_action,
            short_description=short_description,
            vendor_project=vendor_project,
            vulnerability_name=vulnerability_name,
            weaponization_score=weaponization_score,
        )

        kev_entry.additional_properties = d
        return kev_entry

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
