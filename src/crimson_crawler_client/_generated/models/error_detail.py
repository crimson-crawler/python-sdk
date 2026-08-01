from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ErrorDetail")


@_attrs_define
class ErrorDetail:
    """Structured error attached to partial-success responses.

    Attributes:
        error (str): Error classification (e.g. 'timeout', 'unavailable')
        service (str): Data source category that was unavailable (e.g. 'vulnerability-data', 'threat-intelligence')
        step (str): Enrichment step that encountered an error (e.g. 'fetch_epss')
        detail (str | Unset): Human-readable error details Default: ''.
    """

    error: str
    service: str
    step: str
    detail: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        error = self.error

        service = self.service

        step = self.step

        detail = self.detail

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "error": error,
                "service": service,
                "step": step,
            }
        )
        if detail is not UNSET:
            field_dict["detail"] = detail

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        error = d.pop("error")

        service = d.pop("service")

        step = d.pop("step")

        detail = d.pop("detail", UNSET)

        error_detail = cls(
            error=error,
            service=service,
            step=step,
            detail=detail,
        )

        error_detail.additional_properties = d
        return error_detail

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
