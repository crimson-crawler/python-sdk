from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VexOverlayFile")


@_attrs_define
class VexOverlayFile:
    """One VEX suppression-overlay document: OpenVEX 0.2.0 or CSAF 2.0 VEX JSON.

    The overlay annotates findings — it never creates or modifies assets. Parsing happens at submit
    time so a malformed document fails fast with 422 (never a half-finished background job); the
    normalized statements ride on the job and suppress matching findings at enrichment time.

        Attributes:
            content (str): The VEX document text (OpenVEX 0.2.0 or CSAF 2.0 VEX JSON).
            format_ (Literal['vex'] | Unset): Overlay format. Only 'vex' (OpenVEX 0.2.0 / CSAF 2.0 VEX) is accepted today.
                Default: 'vex'.
    """

    content: str
    format_: Literal["vex"] | Unset = "vex"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        content = self.content

        format_ = self.format_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "content": content,
            }
        )
        if format_ is not UNSET:
            field_dict["format"] = format_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        content = d.pop("content")

        format_ = cast(Literal["vex"] | Unset, d.pop("format", UNSET))
        if format_ != "vex" and not isinstance(format_, Unset):
            raise ValueError(f"format must match const 'vex', got '{format_}'")

        vex_overlay_file = cls(
            content=content,
            format_=format_,
        )

        vex_overlay_file.additional_properties = d
        return vex_overlay_file

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
