from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VendorAdvisoryCVSS3")


@_attrs_define
class VendorAdvisoryCVSS3:
    """Red Hat's CVSS v3 block for the CVE.

    Attributes:
        base_score (float | None | str | Unset): Base score
        status (None | str | Unset): Red Hat's scoring status (e.g. 'verified')
        vector (None | str | Unset): Scoring vector
    """

    base_score: float | None | str | Unset = UNSET
    status: None | str | Unset = UNSET
    vector: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        base_score: float | None | str | Unset
        if isinstance(self.base_score, Unset):
            base_score = UNSET
        else:
            base_score = self.base_score

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        vector: None | str | Unset
        if isinstance(self.vector, Unset):
            vector = UNSET
        else:
            vector = self.vector

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if base_score is not UNSET:
            field_dict["base_score"] = base_score
        if status is not UNSET:
            field_dict["status"] = status
        if vector is not UNSET:
            field_dict["vector"] = vector

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_base_score(data: object) -> float | None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | str | Unset, data)

        base_score = _parse_base_score(d.pop("base_score", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vector = _parse_vector(d.pop("vector", UNSET))

        vendor_advisory_cvss3 = cls(
            base_score=base_score,
            status=status,
            vector=vector,
        )

        vendor_advisory_cvss3.additional_properties = d
        return vendor_advisory_cvss3

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
