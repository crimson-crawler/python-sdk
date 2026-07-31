from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.batch_item_result_status import BatchItemResultStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.batch_item_result_data_type_0 import BatchItemResultDataType0
    from ..models.error_detail import ErrorDetail


T = TypeVar("T", bound="BatchItemResult")


@_attrs_define
class BatchItemResult:
    """Result for a single item in a batch enrichment request.

    Attributes:
        identifier (str): Human-readable identifier for the enriched entity
        index (int): Zero-based position of the item in the request `items` list
        status (BatchItemResultStatus): 'ok' when the enrichment ran (per-layer partial failures stay inside
            `data.errors`); 'error' when the item dispatch itself failed
        type_ (str): Enrich type discriminator for the item (e.g. 'cve', 'ioc')
        data (BatchItemResultDataType0 | None | Unset): The matching Enrich<Type>Response payload (by `type`) when
            status='ok'; null when status='error'. Per-layer partial failures are reported inside `data.errors`.
        errors (list[ErrorDetail] | Unset): Dispatch-level failure details — populated only when status='error'
    """

    identifier: str
    index: int
    status: BatchItemResultStatus
    type_: str
    data: BatchItemResultDataType0 | None | Unset = UNSET
    errors: list[ErrorDetail] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.batch_item_result_data_type_0 import BatchItemResultDataType0
        from ..models.error_detail import ErrorDetail

        identifier = self.identifier

        index = self.index

        status = self.status.value

        type_ = self.type_

        data: dict[str, Any] | None | Unset
        if isinstance(self.data, Unset):
            data = UNSET
        elif isinstance(self.data, BatchItemResultDataType0):
            data = self.data.to_dict()
        else:
            data = self.data

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "identifier": identifier,
                "index": index,
                "status": status,
                "type": type_,
            }
        )
        if data is not UNSET:
            field_dict["data"] = data
        if errors is not UNSET:
            field_dict["errors"] = errors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.batch_item_result_data_type_0 import BatchItemResultDataType0
        from ..models.error_detail import ErrorDetail

        d = dict(src_dict)
        identifier = d.pop("identifier")

        index = d.pop("index")

        status = BatchItemResultStatus(d.pop("status"))

        type_ = d.pop("type")

        def _parse_data(data: object) -> BatchItemResultDataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                data_type_0 = BatchItemResultDataType0.from_dict(data)

                return data_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(BatchItemResultDataType0 | None | Unset, data)

        data = _parse_data(d.pop("data", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        batch_item_result = cls(
            identifier=identifier,
            index=index,
            status=status,
            type_=type_,
            data=data,
            errors=errors,
        )

        batch_item_result.additional_properties = d
        return batch_item_result

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
