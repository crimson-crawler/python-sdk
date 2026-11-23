from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CVEReference")


@_attrs_define
class CVEReference:
    """Advisory or reference link carried by a CVE or CWE record.

    Attributes:
        description (str | Unset): The reference's own tag text. NVD uses this as a controlled vocabulary on CVE refs
            ('Patch', 'Exploit', 'Vendor Advisory', 'Third Party Advisory,VDB Entry'), which is how an exploit link is told
            apart from an advisory one; CWE refs leave it empty. Default: ''.
        external_id (str | Unset): External identifier at the source Default: ''.
        source (str | Unset): Reference source name (e.g. 'nvd', 'cve') Default: ''.
        url (str | Unset): Reference URL Default: ''.
    """

    description: str | Unset = ""
    external_id: str | Unset = ""
    source: str | Unset = ""
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description = self.description

        external_id = self.external_id

        source = self.source

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if external_id is not UNSET:
            field_dict["external_id"] = external_id
        if source is not UNSET:
            field_dict["source"] = source
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        description = d.pop("description", UNSET)

        external_id = d.pop("external_id", UNSET)

        source = d.pop("source", UNSET)

        url = d.pop("url", UNSET)

        cve_reference = cls(
            description=description,
            external_id=external_id,
            source=source,
            url=url,
        )

        cve_reference.additional_properties = d
        return cve_reference

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
