from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.batch_item_result import BatchItemResult
    from ..models.error_detail import ErrorDetail


T = TypeVar("T", bound="EnrichBatchResponse")


@_attrs_define
class EnrichBatchResponse:
    """Batch enrichment results, preserving input order.

    Attributes:
        errors (list[ErrorDetail] | Unset): Batch-level (not per-item) failure details
        results (list[BatchItemResult] | Unset): Per-item results in the same order as the request
    """

    errors: list[ErrorDetail] | Unset = UNSET
    results: list[BatchItemResult] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.batch_item_result import BatchItemResult
        from ..models.error_detail import ErrorDetail

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        results: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.results, Unset):
            results = []
            for results_item_data in self.results:
                results_item = results_item_data.to_dict()
                results.append(results_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if errors is not UNSET:
            field_dict["errors"] = errors
        if results is not UNSET:
            field_dict["results"] = results

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.batch_item_result import BatchItemResult
        from ..models.error_detail import ErrorDetail

        d = dict(src_dict)
        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _results = d.pop("results", UNSET)
        results: list[BatchItemResult] | Unset = UNSET
        if _results is not UNSET:
            results = []
            for results_item_data in _results:
                results_item = BatchItemResult.from_dict(results_item_data)

                results.append(results_item)

        enrich_batch_response = cls(
            errors=errors,
            results=results,
        )

        enrich_batch_response.additional_properties = d
        return enrich_batch_response

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
