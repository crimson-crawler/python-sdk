from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="D3FENDDetail")


@_attrs_define
class D3FENDDetail:
    """D3FEND defensive technique or countermeasure.

    Attributes:
        d3fend_form (None | str | Unset): D3FEND form: tactic, mitigation, sub-mitigation, artifact
        d3fend_id (str | Unset): D3FEND identifier (e.g. D3-AL) Default: ''.
        description (None | str | Unset): What this countermeasure does
        linked_techniques (list[str] | Unset): ATT&CK technique IDs this defends against
        name (None | str | Unset): Defensive technique name
        stix_id (None | str | Unset): Unique object identifier for cross-referencing
        url (None | str | Unset): Reference URL
    """

    d3fend_form: None | str | Unset = UNSET
    d3fend_id: str | Unset = ""
    description: None | str | Unset = UNSET
    linked_techniques: list[str] | Unset = UNSET
    name: None | str | Unset = UNSET
    stix_id: None | str | Unset = UNSET
    url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d3fend_form: None | str | Unset
        if isinstance(self.d3fend_form, Unset):
            d3fend_form = UNSET
        else:
            d3fend_form = self.d3fend_form

        d3fend_id = self.d3fend_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        linked_techniques: list[str] | Unset = UNSET
        if not isinstance(self.linked_techniques, Unset):
            linked_techniques = self.linked_techniques

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        stix_id: None | str | Unset
        if isinstance(self.stix_id, Unset):
            stix_id = UNSET
        else:
            stix_id = self.stix_id

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if d3fend_form is not UNSET:
            field_dict["d3fend_form"] = d3fend_form
        if d3fend_id is not UNSET:
            field_dict["d3fend_id"] = d3fend_id
        if description is not UNSET:
            field_dict["description"] = description
        if linked_techniques is not UNSET:
            field_dict["linked_techniques"] = linked_techniques
        if name is not UNSET:
            field_dict["name"] = name
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_d3fend_form(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        d3fend_form = _parse_d3fend_form(d.pop("d3fend_form", UNSET))

        d3fend_id = d.pop("d3fend_id", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        linked_techniques = cast(list[str], d.pop("linked_techniques", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_stix_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stix_id = _parse_stix_id(d.pop("stix_id", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        d3fend_detail = cls(
            d3fend_form=d3fend_form,
            d3fend_id=d3fend_id,
            description=description,
            linked_techniques=linked_techniques,
            name=name,
            stix_id=stix_id,
            url=url,
        )

        d3fend_detail.additional_properties = d
        return d3fend_detail

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
