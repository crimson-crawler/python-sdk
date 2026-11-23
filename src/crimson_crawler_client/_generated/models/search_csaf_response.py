from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.csaf_advisory import CSAFAdvisory
    from ..models.error_detail import ErrorDetail


T = TypeVar("T", bound="SearchCSAFResponse")


@_attrs_define
class SearchCSAFResponse:
    """Response from `/v1/search/csaf`.

    Attributes:
        advisories (list[CSAFAdvisory] | Unset): Matching advisories
        errors (list[ErrorDetail] | Unset): Partial failure details
        total (int | Unset): Unpaginated number of matching advisories Default: 0.
    """

    advisories: list[CSAFAdvisory] | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    total: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.csaf_advisory import CSAFAdvisory  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415

        advisories: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.advisories, Unset):
            advisories = []
            for advisories_item_data in self.advisories:
                advisories_item = advisories_item_data.to_dict()
                advisories.append(advisories_item)

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        total = self.total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if advisories is not UNSET:
            field_dict["advisories"] = advisories
        if errors is not UNSET:
            field_dict["errors"] = errors
        if total is not UNSET:
            field_dict["total"] = total

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.csaf_advisory import CSAFAdvisory  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415

        d = dict(src_dict)
        _advisories = d.pop("advisories", UNSET)
        advisories: list[CSAFAdvisory] | Unset = UNSET
        if _advisories is not UNSET:
            advisories = []
            for advisories_item_data in _advisories:
                advisories_item = CSAFAdvisory.from_dict(advisories_item_data)

                advisories.append(advisories_item)

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        total = d.pop("total", UNSET)

        search_csaf_response = cls(
            advisories=advisories,
            errors=errors,
            total=total,
        )

        search_csaf_response.additional_properties = d
        return search_csaf_response

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
