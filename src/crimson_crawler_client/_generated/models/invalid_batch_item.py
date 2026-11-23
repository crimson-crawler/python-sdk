from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InvalidBatchItem")


@_attrs_define
class InvalidBatchItem:
    """A batch item that no supported enrich type accepted.

    Kept as a member of the request union so ONE malformed item is answered per-item — a
    `status="error"` result naming what failed — instead of rejecting the whole request with a 422.
    That is the same partial-failure shape `BatchItemResult` already documents for dispatch
    failures, and it is what the endpoint's contract ("one item failing does not fail the batch")
    requires: a single typo in item 50 of a 50-item batch must not discard the other 49. The item's
    fields are preserved verbatim so the route can report the validator's own message for it.

        Attributes:
            type_ (Any | Unset): The item's `type` value, preserved as sent so the error can name it — an unrecognized
                discriminator, a missing one, or a non-string value all land here
    """

    type_: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = d.pop("type", UNSET)

        invalid_batch_item = cls(
            type_=type_,
        )

        invalid_batch_item.additional_properties = d
        return invalid_batch_item

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
