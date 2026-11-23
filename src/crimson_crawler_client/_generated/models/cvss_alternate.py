from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CVSSAlternate")


@_attrs_define
class CVSSAlternate:
    """One alternate published CVSS scoring for the same version as the surfaced one.

    Attributes:
        base_score (float | None | Unset): Base score (0.0-10.0)
        base_severity (str | Unset): Severity band (none/low/medium/high/critical) Default: ''.
        entry_type (str | Unset): NVD's Primary/Secondary discriminator for this entry Default: ''.
        source (str | Unset): Who published this scoring (CNA identity id or 'nvd@nist.gov') Default: ''.
        vector_string (str | Unset): Vector string as published Default: ''.
        version (str | Unset): CVSS version this entry scores ('2.0' / '3.0' / '3.1' / '4.0') Default: ''.
    """

    base_score: float | None | Unset = UNSET
    base_severity: str | Unset = ""
    entry_type: str | Unset = ""
    source: str | Unset = ""
    vector_string: str | Unset = ""
    version: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        base_score: float | None | Unset
        if isinstance(self.base_score, Unset):
            base_score = UNSET
        else:
            base_score = self.base_score

        base_severity = self.base_severity

        entry_type = self.entry_type

        source = self.source

        vector_string = self.vector_string

        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if base_score is not UNSET:
            field_dict["base_score"] = base_score
        if base_severity is not UNSET:
            field_dict["base_severity"] = base_severity
        if entry_type is not UNSET:
            field_dict["entry_type"] = entry_type
        if source is not UNSET:
            field_dict["source"] = source
        if vector_string is not UNSET:
            field_dict["vector_string"] = vector_string
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_base_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        base_score = _parse_base_score(d.pop("base_score", UNSET))

        base_severity = d.pop("base_severity", UNSET)

        entry_type = d.pop("entry_type", UNSET)

        source = d.pop("source", UNSET)

        vector_string = d.pop("vector_string", UNSET)

        version = d.pop("version", UNSET)

        cvss_alternate = cls(
            base_score=base_score,
            base_severity=base_severity,
            entry_type=entry_type,
            source=source,
            vector_string=vector_string,
            version=version,
        )

        cvss_alternate.additional_properties = d
        return cvss_alternate

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
