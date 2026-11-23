from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SourceStamp")


@_attrs_define
class SourceStamp:
    """Which source supplied which fields, and how current that source's data was (W3C PROV-style).

    Attributes:
        source (str): Source dataset (e.g. 'NVD', 'FIRST EPSS', 'CISA KEV', 'OSV.dev')
        as_of (None | str | Unset): The source's own currency date for this record, when it states one (NVD last-
            modified, EPSS score date, KEV catalog release, Metasploit/Nuclei retrieval). Null when the source gives none
        fields (list[str] | Unset): The fields on this record that came from the source
    """

    source: str
    as_of: None | str | Unset = UNSET
    fields: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source = self.source

        as_of: None | str | Unset
        if isinstance(self.as_of, Unset):
            as_of = UNSET
        else:
            as_of = self.as_of

        fields: list[str] | Unset = UNSET
        if not isinstance(self.fields, Unset):
            fields = self.fields

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source": source,
            }
        )
        if as_of is not UNSET:
            field_dict["as_of"] = as_of
        if fields is not UNSET:
            field_dict["fields"] = fields

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source = d.pop("source")

        def _parse_as_of(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        as_of = _parse_as_of(d.pop("as_of", UNSET))

        fields = cast(list[str], d.pop("fields", UNSET))

        source_stamp = cls(
            source=source,
            as_of=as_of,
            fields=fields,
        )

        source_stamp.additional_properties = d
        return source_stamp

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
