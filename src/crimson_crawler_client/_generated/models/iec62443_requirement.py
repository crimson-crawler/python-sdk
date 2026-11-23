from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IEC62443Requirement")


@_attrs_define
class IEC62443Requirement:
    """One CWE-1424 mapping: a weakness and the ISA/IEC 62443 requirement it violates.

    CWE-1424 is an implicit view in MITRE's catalog: its members are exactly the
    Weaknesses carrying a ``Taxonomy_Mapping`` for ``ISA/IEC 62443``. ``part`` is
    that mapping's ``Entry_ID`` (``Part 4-2``) and ``requirement`` its
    ``Entry_Name`` (``CR 3.5``). ``cwe_id`` is set on the per-weakness list and
    left null on the aggregated ``ot_context.iec_62443.requirements`` rows, which
    carry ``cwe_ids`` instead.

        Attributes:
            requirement (str): Requirement id within the part (e.g. 'CR 3.5')
            cwe_id (None | str | Unset): The mapped CWE on a per-weakness row
            cwe_ids (list[str] | Unset): Mapped CWEs on an aggregated row
            part (None | str | Unset): ISA/IEC 62443 part (e.g. 'Part 4-2')
            source (str | Unset): Stable source label Default: 'CWE-1424'.
            source_url (str | Unset): The ISA/IEC 62443 view this mapping comes from Default:
                'https://cwe.mitre.org/data/definitions/1424.html'.
            url (str | Unset): The CWE definition page Default: ''.
    """

    requirement: str
    cwe_id: None | str | Unset = UNSET
    cwe_ids: list[str] | Unset = UNSET
    part: None | str | Unset = UNSET
    source: str | Unset = "CWE-1424"
    source_url: str | Unset = "https://cwe.mitre.org/data/definitions/1424.html"
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        requirement = self.requirement

        cwe_id: None | str | Unset
        if isinstance(self.cwe_id, Unset):
            cwe_id = UNSET
        else:
            cwe_id = self.cwe_id

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        part: None | str | Unset
        if isinstance(self.part, Unset):
            part = UNSET
        else:
            part = self.part

        source = self.source

        source_url = self.source_url

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "requirement": requirement,
            }
        )
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if part is not UNSET:
            field_dict["part"] = part
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
        requirement = d.pop("requirement")

        def _parse_cwe_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cwe_id = _parse_cwe_id(d.pop("cwe_id", UNSET))

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        def _parse_part(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        part = _parse_part(d.pop("part", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        url = d.pop("url", UNSET)

        iec62443_requirement = cls(
            requirement=requirement,
            cwe_id=cwe_id,
            cwe_ids=cwe_ids,
            part=part,
            source=source,
            source_url=source_url,
            url=url,
        )

        iec62443_requirement.additional_properties = d
        return iec62443_requirement

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
