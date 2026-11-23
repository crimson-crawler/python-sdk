from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EMB3DThreat")


@_attrs_define
class EMB3DThreat:
    """One MITRE EMB3D embedded/hardware threat, indexed by the CWE ids it names.

    EMB3D publishes its threats as STIX 2.1 `vulnerability` objects and its
    countermeasures as `course-of-action` objects joined by `mitigates`
    relationships; both are reproduced here with MITRE attribution.

        Attributes:
            id (str): The threat's STIX id
            name (str): Threat name
            source_url (str): The committed dataset's upstream URL
            cwe_ids (list[str] | Unset): CWE ids the threat names
            description (None | str | Unset): Threat description
            mitigations (list[str] | Unset): EMB3D countermeasure names joined to this threat
            source (str | Unset): Stable source label Default: 'emb3d'.
            technique_ids (list[str] | Unset): ATT&CK ids the threat names, when EMB3D carries them
    """

    id: str
    name: str
    source_url: str
    cwe_ids: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    mitigations: list[str] | Unset = UNSET
    source: str | Unset = "emb3d"
    technique_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        source_url = self.source_url

        cwe_ids: list[str] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        mitigations: list[str] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = self.mitigations

        source = self.source

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "source_url": source_url,
            }
        )
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if description is not UNSET:
            field_dict["description"] = description
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if source is not UNSET:
            field_dict["source"] = source
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        source_url = d.pop("source_url")

        cwe_ids = cast(list[str], d.pop("cwe_ids", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        mitigations = cast(list[str], d.pop("mitigations", UNSET))

        source = d.pop("source", UNSET)

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        emb3d_threat = cls(
            id=id,
            name=name,
            source_url=source_url,
            cwe_ids=cwe_ids,
            description=description,
            mitigations=mitigations,
            source=source,
            technique_ids=technique_ids,
        )

        emb3d_threat.additional_properties = d
        return emb3d_threat

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
