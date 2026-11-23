from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogSourceGroup")


@_attrs_define
class LogSourceGroup:
    """One log source and every channel of it that observes a technique (ATT&CK v18 data components).

    Attributes:
        channels (list[str] | Unset): Channels / event ids / paths read inside that source
        name (str | Unset): Log source (e.g. 'WinEventLog:Security', 'auditd:SYSCALL') Default: ''.
    """

    channels: list[str] | Unset = UNSET
    name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        channels: list[str] | Unset = UNSET
        if not isinstance(self.channels, Unset):
            channels = self.channels

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if channels is not UNSET:
            field_dict["channels"] = channels
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        channels = cast(list[str], d.pop("channels", UNSET))

        name = d.pop("name", UNSET)

        log_source_group = cls(
            channels=channels,
            name=name,
        )

        log_source_group.additional_properties = d
        return log_source_group

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
