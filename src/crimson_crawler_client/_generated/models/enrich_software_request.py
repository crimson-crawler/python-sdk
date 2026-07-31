from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.enrich_software_request_framework import EnrichSoftwareRequestFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichSoftwareRequest")


@_attrs_define
class EnrichSoftwareRequest:
    """Look up or search malware and tools with their techniques and associated groups.

    Attributes:
        framework (EnrichSoftwareRequestFramework | Unset): ATT&CK framework: enterprise, ics, or mobile Default:
            EnrichSoftwareRequestFramework.ENTERPRISE.
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, details, detections, groups, knowledgebase, misp, mitigations, navigator, nist_controls, summary,
            techniques, tie, web, web_scrape.
        search (None | str | Unset): Text query to search by name or alias (e.g. 'Cobalt Strike')
        software_id (None | str | Unset): ATT&CK software ID for direct lookup (e.g. S0154)
    """

    framework: EnrichSoftwareRequestFramework | Unset = EnrichSoftwareRequestFramework.ENTERPRISE
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    software_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework: str | Unset = UNSET
        if not isinstance(self.framework, Unset):
            framework = self.framework.value

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        search: None | str | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        else:
            search = self.search

        software_id: None | str | Unset
        if isinstance(self.software_id, Unset):
            software_id = UNSET
        else:
            software_id = self.software_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if framework is not UNSET:
            field_dict["framework"] = framework
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search
        if software_id is not UNSET:
            field_dict["software_id"] = software_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _framework = d.pop("framework", UNSET)
        framework: EnrichSoftwareRequestFramework | Unset
        if isinstance(_framework, Unset):
            framework = UNSET
        else:
            framework = EnrichSoftwareRequestFramework(_framework)

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        def _parse_software_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        software_id = _parse_software_id(d.pop("software_id", UNSET))

        enrich_software_request = cls(
            framework=framework,
            include=include,
            search=search,
            software_id=software_id,
        )

        enrich_software_request.additional_properties = d
        return enrich_software_request

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
