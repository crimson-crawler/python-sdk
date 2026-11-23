from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogSource")


@_attrs_define
class LogSource:
    """One recordable location for a technique's data source.

    ``name`` is the log source (``WinEventLog:TaskScheduler``, ``linux:cron``) and ``channel`` is
    where it is read inside that source — an event-log channel or a path; empty when the source
    names no channel.

        Attributes:
            channel (str | Unset): Where the source is read from; empty when no channel is named Default: ''.
            name (str | Unset): Log source name (e.g. 'WinEventLog:TaskScheduler', 'linux:cron') Default: ''.
    """

    channel: str | Unset = ""
    name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        channel = self.channel

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if channel is not UNSET:
            field_dict["channel"] = channel
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        channel = d.pop("channel", UNSET)

        name = d.pop("name", UNSET)

        log_source = cls(
            channel=channel,
            name=name,
        )

        log_source.additional_properties = d
        return log_source

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
