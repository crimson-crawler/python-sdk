from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichCWERequest")


@_attrs_define
class EnrichCWERequest:
    """Enrich a weakness classification with linked attack patterns and adversary techniques.

    Attributes:
        cwe_id (str): CWE identifier (e.g. CWE-79)
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            capecs, cves, defend, details, detections, groups, knowledgebase, mitigations, navigator, nist_controls,
            software, summary, techniques, tie, web, web_scrape.
    """

    cwe_id: str
    include: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cwe_id = self.cwe_id

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cwe_id": cwe_id,
            }
        )
        if include is not UNSET:
            field_dict["include"] = include

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cwe_id = d.pop("cwe_id")

        include = cast(list[str], d.pop("include", UNSET))

        enrich_cwe_request = cls(
            cwe_id=cwe_id,
            include=include,
        )

        enrich_cwe_request.additional_properties = d
        return enrich_cwe_request

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
