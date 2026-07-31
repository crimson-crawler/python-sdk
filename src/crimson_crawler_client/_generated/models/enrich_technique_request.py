from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.enrich_technique_request_framework import EnrichTechniqueRequestFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichTechniqueRequest")


@_attrs_define
class EnrichTechniqueRequest:
    """Retrieve ATT&CK technique details with threat predictions and related intelligence.

    Attributes:
        framework (EnrichTechniqueRequestFramework | Unset): ATT&CK framework: enterprise, ics, or mobile Default:
            EnrichTechniqueRequestFramework.ENTERPRISE.
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, details, detections, groups, knowledgebase, misp, mitigations, navigator, nist_controls, software,
            summary, tie, web, web_scrape.
        search (None | str | Unset): Text query to search techniques by name or description
        technique_id (None | str | Unset): Single technique ID for direct lookup (e.g. T1190)
        technique_ids (list[str] | None | Unset): List of technique IDs for batch lookup (max 50)
    """

    framework: EnrichTechniqueRequestFramework | Unset = EnrichTechniqueRequestFramework.ENTERPRISE
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    technique_id: None | str | Unset = UNSET
    technique_ids: list[str] | None | Unset = UNSET
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

        technique_id: None | str | Unset
        if isinstance(self.technique_id, Unset):
            technique_id = UNSET
        else:
            technique_id = self.technique_id

        technique_ids: list[str] | None | Unset
        if isinstance(self.technique_ids, Unset):
            technique_ids = UNSET
        elif isinstance(self.technique_ids, list):
            technique_ids = self.technique_ids

        else:
            technique_ids = self.technique_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if framework is not UNSET:
            field_dict["framework"] = framework
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search
        if technique_id is not UNSET:
            field_dict["technique_id"] = technique_id
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _framework = d.pop("framework", UNSET)
        framework: EnrichTechniqueRequestFramework | Unset
        if isinstance(_framework, Unset):
            framework = UNSET
        else:
            framework = EnrichTechniqueRequestFramework(_framework)

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        def _parse_technique_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        technique_id = _parse_technique_id(d.pop("technique_id", UNSET))

        def _parse_technique_ids(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                technique_ids_type_0 = cast(list[str], data)

                return technique_ids_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        technique_ids = _parse_technique_ids(d.pop("technique_ids", UNSET))

        enrich_technique_request = cls(
            framework=framework,
            include=include,
            search=search,
            technique_id=technique_id,
            technique_ids=technique_ids,
        )

        enrich_technique_request.additional_properties = d
        return enrich_technique_request

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
