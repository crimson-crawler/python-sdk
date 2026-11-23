from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InventoryMetasploitModule")


@_attrs_define
class InventoryMetasploitModule:
    """Compact Metasploit module reference on an inventory CVE (the full record lives on `/v1/enrich/cve`).

    Attributes:
        attribution (str | Unset): Upstream copyright notice Default: 'Copyright 2006-2026 Rapid7, Inc.'.
        is_scada (bool | Unset): Whether the module targets OT/ICS tooling Default: False.
        licence (str | Unset): Licence for the framework metadata Default: 'BSD-3-Clause'.
        licence_url (str | Unset): Licence text Default: 'https://github.com/rapid7/metasploit-
            framework/blob/master/LICENSE'.
        module_path (str | Unset): Canonical `use` path Default: ''.
        name (None | str | Unset): Module title
        rank_label (None | str | Unset): Framework quality rank (Manual … Excellent)
        source (str | Unset): Provenance label Default: 'metasploit'.
        source_url (str | Unset): Metadata source Default: 'https://raw.githubusercontent.com/rapid7/metasploit-
            framework/master/db/modules_metadata_base.json'.
    """

    attribution: str | Unset = "Copyright 2006-2026 Rapid7, Inc."
    is_scada: bool | Unset = False
    licence: str | Unset = "BSD-3-Clause"
    licence_url: str | Unset = "https://github.com/rapid7/metasploit-framework/blob/master/LICENSE"
    module_path: str | Unset = ""
    name: None | str | Unset = UNSET
    rank_label: None | str | Unset = UNSET
    source: str | Unset = "metasploit"
    source_url: str | Unset = (
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    )
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attribution = self.attribution

        is_scada = self.is_scada

        licence = self.licence

        licence_url = self.licence_url

        module_path = self.module_path

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        rank_label: None | str | Unset
        if isinstance(self.rank_label, Unset):
            rank_label = UNSET
        else:
            rank_label = self.rank_label

        source = self.source

        source_url = self.source_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if is_scada is not UNSET:
            field_dict["is_scada"] = is_scada
        if licence is not UNSET:
            field_dict["licence"] = licence
        if licence_url is not UNSET:
            field_dict["licence_url"] = licence_url
        if module_path is not UNSET:
            field_dict["module_path"] = module_path
        if name is not UNSET:
            field_dict["name"] = name
        if rank_label is not UNSET:
            field_dict["rank_label"] = rank_label
        if source is not UNSET:
            field_dict["source"] = source
        if source_url is not UNSET:
            field_dict["source_url"] = source_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        attribution = d.pop("attribution", UNSET)

        is_scada = d.pop("is_scada", UNSET)

        licence = d.pop("licence", UNSET)

        licence_url = d.pop("licence_url", UNSET)

        module_path = d.pop("module_path", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_rank_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        rank_label = _parse_rank_label(d.pop("rank_label", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        inventory_metasploit_module = cls(
            attribution=attribution,
            is_scada=is_scada,
            licence=licence,
            licence_url=licence_url,
            module_path=module_path,
            name=name,
            rank_label=rank_label,
            source=source,
            source_url=source_url,
        )

        inventory_metasploit_module.additional_properties = d
        return inventory_metasploit_module

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
