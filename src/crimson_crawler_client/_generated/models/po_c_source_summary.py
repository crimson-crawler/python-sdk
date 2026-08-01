from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PoCSourceSummary")


@_attrs_define
class PoCSourceSummary:
    """Structured AI-assisted analysis of a PoC repository. Raw source code is not returned.

    Attributes:
        affected_path (None | str | Unset): Function, endpoint, or call path the exploit reaches
        mitigation (None | str | Unset): Mitigation advice referenced by the source, if any
        preconditions (list[str] | Unset): Environmental, authentication, or configuration requirements
        trigger (None | str | Unset): Condition or input that triggers the vulnerability
    """

    affected_path: None | str | Unset = UNSET
    mitigation: None | str | Unset = UNSET
    preconditions: list[str] | Unset = UNSET
    trigger: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        affected_path: None | str | Unset
        if isinstance(self.affected_path, Unset):
            affected_path = UNSET
        else:
            affected_path = self.affected_path

        mitigation: None | str | Unset
        if isinstance(self.mitigation, Unset):
            mitigation = UNSET
        else:
            mitigation = self.mitigation

        preconditions: list[str] | Unset = UNSET
        if not isinstance(self.preconditions, Unset):
            preconditions = self.preconditions

        trigger: None | str | Unset
        if isinstance(self.trigger, Unset):
            trigger = UNSET
        else:
            trigger = self.trigger

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if affected_path is not UNSET:
            field_dict["affected_path"] = affected_path
        if mitigation is not UNSET:
            field_dict["mitigation"] = mitigation
        if preconditions is not UNSET:
            field_dict["preconditions"] = preconditions
        if trigger is not UNSET:
            field_dict["trigger"] = trigger

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_affected_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        affected_path = _parse_affected_path(d.pop("affected_path", UNSET))

        def _parse_mitigation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        mitigation = _parse_mitigation(d.pop("mitigation", UNSET))

        preconditions = cast(list[str], d.pop("preconditions", UNSET))

        def _parse_trigger(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        trigger = _parse_trigger(d.pop("trigger", UNSET))

        po_c_source_summary = cls(
            affected_path=affected_path,
            mitigation=mitigation,
            preconditions=preconditions,
            trigger=trigger,
        )

        po_c_source_summary.additional_properties = d
        return po_c_source_summary

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
