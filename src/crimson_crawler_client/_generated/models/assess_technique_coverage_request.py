from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.assess_technique_coverage_request_framework import AssessTechniqueCoverageRequestFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessTechniqueCoverageRequest")


@_attrs_define
class AssessTechniqueCoverageRequest:
    """Batch-assess ATT&CK techniques: mitigations, detections, and threat predictions in one call.

    Attributes:
        technique_ids (list[str]): List of ATT&CK technique IDs to assess (max 50)
        framework (AssessTechniqueCoverageRequestFramework | Unset): ATT&CK framework: enterprise, ics, or mobile
            Default: AssessTechniqueCoverageRequestFramework.ENTERPRISE.
        include (list[str] | Unset): Assessment layers to include. Replaces the default list. Allowed values:
            coverage_score, cves, defend, detections, mitigations, navigator, nist_controls, summary, tie.
    """

    technique_ids: list[str]
    framework: AssessTechniqueCoverageRequestFramework | Unset = AssessTechniqueCoverageRequestFramework.ENTERPRISE
    include: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        technique_ids = self.technique_ids

        framework: str | Unset = UNSET
        if not isinstance(self.framework, Unset):
            framework = self.framework.value

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique_ids": technique_ids,
            }
        )
        if framework is not UNSET:
            field_dict["framework"] = framework
        if include is not UNSET:
            field_dict["include"] = include

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        technique_ids = cast(list[str], d.pop("technique_ids"))

        _framework = d.pop("framework", UNSET)
        framework: AssessTechniqueCoverageRequestFramework | Unset
        if isinstance(_framework, Unset):
            framework = UNSET
        else:
            framework = AssessTechniqueCoverageRequestFramework(_framework)

        include = cast(list[str], d.pop("include", UNSET))

        assess_technique_coverage_request = cls(
            technique_ids=technique_ids,
            framework=framework,
            include=include,
        )

        assess_technique_coverage_request.additional_properties = d
        return assess_technique_coverage_request

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
