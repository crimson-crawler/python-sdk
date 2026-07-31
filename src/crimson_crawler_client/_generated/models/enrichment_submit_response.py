from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichmentSubmitResponse")


@_attrs_define
class EnrichmentSubmitResponse:
    """Accepted asynchronous enrichment.

    Attributes:
        enrichment_id (str): Identifier to poll on the matching status endpoint
        status (Literal['queued'] | Unset): The job was accepted and is waiting to run Default: 'queued'.
    """

    enrichment_id: str
    status: Literal["queued"] | Unset = "queued"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enrichment_id = self.enrichment_id

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "enrichment_id": enrichment_id,
            }
        )
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        enrichment_id = d.pop("enrichment_id")

        status = cast(Literal["queued"] | Unset, d.pop("status", UNSET))
        if status != "queued" and not isinstance(status, Unset):
            raise ValueError(f"status must match const 'queued', got '{status}'")

        enrichment_submit_response = cls(
            enrichment_id=enrichment_id,
            status=status,
        )

        enrichment_submit_response.additional_properties = d
        return enrichment_submit_response

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
