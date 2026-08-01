from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.enrich_group_request_framework import EnrichGroupRequestFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichGroupRequest")


@_attrs_define
class EnrichGroupRequest:
    """Look up or search threat actor groups with their techniques and tooling.

    Attributes:
        framework (EnrichGroupRequestFramework | Unset): ATT&CK framework: enterprise, ics, or mobile Default:
            EnrichGroupRequestFramework.ENTERPRISE.
        group_id (None | str | Unset): ATT&CK group ID for direct lookup (e.g. G0016)
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, details, detections, knowledgebase, locations, misp, mitigations, navigator, nist_controls,
            sectors, software, summary, techniques, tie, web, web_scrape.
        search (None | str | Unset): Text query to search groups by name or alias (e.g. 'APT28')
    """

    framework: EnrichGroupRequestFramework | Unset = EnrichGroupRequestFramework.ENTERPRISE
    group_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework: str | Unset = UNSET
        if not isinstance(self.framework, Unset):
            framework = self.framework.value

        group_id: None | str | Unset
        if isinstance(self.group_id, Unset):
            group_id = UNSET
        else:
            group_id = self.group_id

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        search: None | str | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        else:
            search = self.search

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if framework is not UNSET:
            field_dict["framework"] = framework
        if group_id is not UNSET:
            field_dict["group_id"] = group_id
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _framework = d.pop("framework", UNSET)
        framework: EnrichGroupRequestFramework | Unset
        if isinstance(_framework, Unset):
            framework = UNSET
        else:
            framework = EnrichGroupRequestFramework(_framework)

        def _parse_group_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        group_id = _parse_group_id(d.pop("group_id", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        enrich_group_request = cls(
            framework=framework,
            group_id=group_id,
            include=include,
            search=search,
        )

        enrich_group_request.additional_properties = d
        return enrich_group_request

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
