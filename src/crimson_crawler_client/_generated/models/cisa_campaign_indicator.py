from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CISACampaignIndicator")


@_attrs_define
class CISACampaignIndicator:
    """One observable a CISA joint-advisory STIX bundle publishes, normalised from its pattern.

    A STIX `indicator` may hold an OR/AND expression with several observables; each simple
    equality clause becomes one row, so a hash pair in one indicator still matches either hash.

        Attributes:
            type_ (str): Observable type: `ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`, `mutex` or
                `filename` — normalised from the STIX object type and property path
            value (str): The observable value, lower-cased
            name (None | str | Unset): The parent STIX indicator object's name, as published
    """

    type_: str
    value: str
    name: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_

        value = self.value

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "value": value,
            }
        )
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = d.pop("type")

        value = d.pop("value")

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        cisa_campaign_indicator = cls(
            type_=type_,
            value=value,
            name=name,
        )

        cisa_campaign_indicator.additional_properties = d
        return cisa_campaign_indicator

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
