from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CNAIdentity")


@_attrs_define
class CNAIdentity:
    """A CVE Numbering Authority — who assigns CVEs, and how to reach them.

    Attributes:
        contact_information (None | str | Unset): CNA contact (usually the security@ alias)
        identity_class (str | Unset): STIX identity_class Default: ''.
        identity_id (str | Unset): STIX identity id (the `created_by_ref` CVEs carry) Default: ''.
        name (str | Unset): CNA name (e.g. 'Apache Software Foundation') Default: ''.
    """

    contact_information: None | str | Unset = UNSET
    identity_class: str | Unset = ""
    identity_id: str | Unset = ""
    name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        contact_information: None | str | Unset
        if isinstance(self.contact_information, Unset):
            contact_information = UNSET
        else:
            contact_information = self.contact_information

        identity_class = self.identity_class

        identity_id = self.identity_id

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if contact_information is not UNSET:
            field_dict["contact_information"] = contact_information
        if identity_class is not UNSET:
            field_dict["identity_class"] = identity_class
        if identity_id is not UNSET:
            field_dict["identity_id"] = identity_id
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_contact_information(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        contact_information = _parse_contact_information(d.pop("contact_information", UNSET))

        identity_class = d.pop("identity_class", UNSET)

        identity_id = d.pop("identity_id", UNSET)

        name = d.pop("name", UNSET)

        cna_identity = cls(
            contact_information=contact_information,
            identity_class=identity_class,
            identity_id=identity_id,
            name=name,
        )

        cna_identity.additional_properties = d
        return cna_identity

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
