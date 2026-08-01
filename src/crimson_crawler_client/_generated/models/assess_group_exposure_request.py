from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.assess_group_exposure_request_framework import AssessGroupExposureRequestFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessGroupExposureRequest")


@_attrs_define
class AssessGroupExposureRequest:
    """Assess the combined technique surface across multiple threat groups.

    Attributes:
        framework (AssessGroupExposureRequestFramework | Unset): ATT&CK framework: enterprise, ics, or mobile Default:
            AssessGroupExposureRequestFramework.ENTERPRISE.
        group_ids (list[str] | None | Unset): List of ATT&CK group IDs (e.g. ['G0016', 'G0032'])
        include (list[str] | Unset): Assessment layers to include. Replaces the default list. Allowed values: cves,
            defend, details, locations, navigator, nist_controls, sectors, summary, techniques, tie.
        search (list[str] | None | Unset): List of group names to search (e.g. ['APT28', 'Lazarus Group'])
    """

    framework: AssessGroupExposureRequestFramework | Unset = AssessGroupExposureRequestFramework.ENTERPRISE
    group_ids: list[str] | None | Unset = UNSET
    include: list[str] | Unset = UNSET
    search: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework: str | Unset = UNSET
        if not isinstance(self.framework, Unset):
            framework = self.framework.value

        group_ids: list[str] | None | Unset
        if isinstance(self.group_ids, Unset):
            group_ids = UNSET
        elif isinstance(self.group_ids, list):
            group_ids = self.group_ids

        else:
            group_ids = self.group_ids

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        search: list[str] | None | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        elif isinstance(self.search, list):
            search = self.search

        else:
            search = self.search

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if framework is not UNSET:
            field_dict["framework"] = framework
        if group_ids is not UNSET:
            field_dict["group_ids"] = group_ids
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _framework = d.pop("framework", UNSET)
        framework: AssessGroupExposureRequestFramework | Unset
        if isinstance(_framework, Unset):
            framework = UNSET
        else:
            framework = AssessGroupExposureRequestFramework(_framework)

        def _parse_group_ids(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                group_ids_type_0 = cast(list[str], data)

                return group_ids_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        group_ids = _parse_group_ids(d.pop("group_ids", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                search_type_0 = cast(list[str], data)

                return search_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        assess_group_exposure_request = cls(
            framework=framework,
            group_ids=group_ids,
            include=include,
            search=search,
        )

        assess_group_exposure_request.additional_properties = d
        return assess_group_exposure_request

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
