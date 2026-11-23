from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ICSWeakness")


@_attrs_define
class ICSWeakness:
    """One CWE that belongs to MITRE's CWE-1358 ICS weakness view.

    Membership is read from the committed CWE catalog projection (view 1358,
    built by ``scripts/build_cwe_ics_data.py``), not inferred from a product name.
    Returned under the ``weakness_ranks`` token.

        Attributes:
            cwe_id (str): The CWE id (e.g. 'CWE-121')
            name (None | str | Unset): The catalog's weakness name
            source (str | Unset): Stable source label Default: 'CWE-1358'.
            source_url (str | Unset): The ICS view this membership comes from Default:
                'https://cwe.mitre.org/data/definitions/1358.html'.
            url (str | Unset): The CWE definition page Default: ''.
    """

    cwe_id: str
    name: None | str | Unset = UNSET
    source: str | Unset = "CWE-1358"
    source_url: str | Unset = "https://cwe.mitre.org/data/definitions/1358.html"
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cwe_id = self.cwe_id

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        source = self.source

        source_url = self.source_url

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cwe_id": cwe_id,
            }
        )
        if name is not UNSET:
            field_dict["name"] = name
        if source is not UNSET:
            field_dict["source"] = source
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cwe_id = d.pop("cwe_id")

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        url = d.pop("url", UNSET)

        ics_weakness = cls(
            cwe_id=cwe_id,
            name=name,
            source=source,
            source_url=source_url,
            url=url,
        )

        ics_weakness.additional_properties = d
        return ics_weakness

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
