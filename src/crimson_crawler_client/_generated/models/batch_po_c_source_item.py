from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchPoCSourceItem")


@_attrs_define
class BatchPoCSourceItem:
    """Batch item: fetch and summarize a PoC source repository.

    Attributes:
        repo_url (str): GitHub repository URL
        type_ (Literal['poc_source'] | Unset): Selects PoC source analysis for this batch item Default: 'poc_source'.
    """

    repo_url: str
    type_: Literal["poc_source"] | Unset = "poc_source"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_url = self.repo_url

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_url": repo_url,
            }
        )
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_url = d.pop("repo_url")

        type_ = cast(Literal["poc_source"] | Unset, d.pop("type", UNSET))
        if type_ != "poc_source" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'poc_source', got '{type_}'")

        batch_po_c_source_item = cls(
            repo_url=repo_url,
            type_=type_,
        )

        batch_po_c_source_item.additional_properties = d
        return batch_po_c_source_item

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
