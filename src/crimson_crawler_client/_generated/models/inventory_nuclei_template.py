from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InventoryNucleiTemplate")


@_attrs_define
class InventoryNucleiTemplate:
    """Compact Nuclei template reference on an inventory CVE.

    Attributes:
        attribution (str | Unset): Upstream copyright notice Default: 'Copyright 2025 ProjectDiscovery, Inc.'.
        id (str | Unset): Template id Default: ''.
        licence (str | Unset): Licence for the template metadata Default: 'MIT'.
        licence_url (str | Unset): Licence text Default: 'https://github.com/projectdiscovery/nuclei-
            templates/blob/main/LICENSE.md'.
        name (None | str | Unset): Template name
        ot_protocols (list[str] | Unset): Curated OT protocol ids the template names
        severity (None | str | Unset): Template severity (info → critical)
        source (str | Unset): Provenance label Default: 'nuclei_templates'.
        source_url (str | Unset): Template source URL Default: ''.
        verified (bool | None | Unset): Whether the source marks the template verified
    """

    attribution: str | Unset = "Copyright 2025 ProjectDiscovery, Inc."
    id: str | Unset = ""
    licence: str | Unset = "MIT"
    licence_url: str | Unset = "https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md"
    name: None | str | Unset = UNSET
    ot_protocols: list[str] | Unset = UNSET
    severity: None | str | Unset = UNSET
    source: str | Unset = "nuclei_templates"
    source_url: str | Unset = ""
    verified: bool | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attribution = self.attribution

        id = self.id

        licence = self.licence

        licence_url = self.licence_url

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        ot_protocols: list[str] | Unset = UNSET
        if not isinstance(self.ot_protocols, Unset):
            ot_protocols = self.ot_protocols

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        source = self.source

        source_url = self.source_url

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
        if id is not UNSET:
            field_dict["id"] = id
        if licence is not UNSET:
            field_dict["licence"] = licence
        if licence_url is not UNSET:
            field_dict["licence_url"] = licence_url
        if name is not UNSET:
            field_dict["name"] = name
        if ot_protocols is not UNSET:
            field_dict["ot_protocols"] = ot_protocols
        if severity is not UNSET:
            field_dict["severity"] = severity
        if source is not UNSET:
            field_dict["source"] = source
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if verified is not UNSET:
            field_dict["verified"] = verified

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        attribution = d.pop("attribution", UNSET)

        id = d.pop("id", UNSET)

        licence = d.pop("licence", UNSET)

        licence_url = d.pop("licence_url", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        ot_protocols = cast(list[str], d.pop("ot_protocols", UNSET))

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        def _parse_verified(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        verified = _parse_verified(d.pop("verified", UNSET))

        inventory_nuclei_template = cls(
            attribution=attribution,
            id=id,
            licence=licence,
            licence_url=licence_url,
            name=name,
            ot_protocols=ot_protocols,
            severity=severity,
            source=source,
            source_url=source_url,
            verified=verified,
        )

        inventory_nuclei_template.additional_properties = d
        return inventory_nuclei_template

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
