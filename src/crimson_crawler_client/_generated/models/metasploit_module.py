from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MetasploitModule")


@_attrs_define
class MetasploitModule:
    """One Metasploit Framework module that references the CVE, as published metadata.

    The framework's own quality rank is the strongest available weaponisation signal and one
    ExploitDB's `verified` boolean does not carry; `reliability` / `stability` / `side_effects` are
    the module's declared notes — the effect it has on a target. No module source is read.

        Attributes:
            archs (list[str] | Unset): Architectures the module declares
            attribution (str | Unset): Upstream copyright notice Default: 'Copyright 2006-2026 Rapid7, Inc.'.
            disclosure_date (None | str | Unset): Module disclosure date
            is_scada (bool | Unset): Whether the module path/name targets OT/ICS tooling: a `scada`/`ics`/`plc` segment, a
                curated OT protocol name, or a curated OT vendor name. Default: False.
            licence (str | Unset): Licence for the framework metadata Default: 'BSD-3-Clause'.
            licence_url (str | Unset): Licence text Default: 'https://github.com/rapid7/metasploit-
                framework/blob/master/LICENSE'.
            modified (None | str | Unset): Last modification time of the module file
            module_file (None | str | Unset): The module's `.rb` location in the framework tree
            module_path (str | Unset): Canonical `use` path (e.g. 'exploit/multi/http/log4shell_header_injection') Default:
                ''.
            module_type (None | str | Unset): Module kind: exploit, auxiliary, post, …
            name (None | str | Unset): Module title
            platforms (list[str] | Unset): Platforms the module declares
            rank (int | None | Unset): Raw rank (0 Manual … 600 Excellent)
            rank_label (None | str | Unset): Rank as the framework labels it (e.g. 'Great')
            ref_name (None | str | Unset): Framework reference name
            references (list[str] | Unset): The module's own reference list (includes the CVE id)
            reliability (list[str] | Unset): Declared reliability notes
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            side_effects (list[str] | Unset): Declared side effects on the target
            source (str | Unset): Provenance label Default: 'metasploit'.
            source_url (str | Unset): URL the metadata was read from Default: ''.
            stability (list[str] | Unset): Declared stability notes
            targets (list[str] | Unset): Target names the module declares
    """

    archs: list[str] | Unset = UNSET
    attribution: str | Unset = "Copyright 2006-2026 Rapid7, Inc."
    disclosure_date: None | str | Unset = UNSET
    is_scada: bool | Unset = False
    licence: str | Unset = "BSD-3-Clause"
    licence_url: str | Unset = "https://github.com/rapid7/metasploit-framework/blob/master/LICENSE"
    modified: None | str | Unset = UNSET
    module_file: None | str | Unset = UNSET
    module_path: str | Unset = ""
    module_type: None | str | Unset = UNSET
    name: None | str | Unset = UNSET
    platforms: list[str] | Unset = UNSET
    rank: int | None | Unset = UNSET
    rank_label: None | str | Unset = UNSET
    ref_name: None | str | Unset = UNSET
    references: list[str] | Unset = UNSET
    reliability: list[str] | Unset = UNSET
    retrieved_at: str | Unset = ""
    side_effects: list[str] | Unset = UNSET
    source: str | Unset = "metasploit"
    source_url: str | Unset = ""
    stability: list[str] | Unset = UNSET
    targets: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        archs: list[str] | Unset = UNSET
        if not isinstance(self.archs, Unset):
            archs = self.archs

        attribution = self.attribution

        disclosure_date: None | str | Unset
        if isinstance(self.disclosure_date, Unset):
            disclosure_date = UNSET
        else:
            disclosure_date = self.disclosure_date

        is_scada = self.is_scada

        licence = self.licence

        licence_url = self.licence_url

        modified: None | str | Unset
        if isinstance(self.modified, Unset):
            modified = UNSET
        else:
            modified = self.modified

        module_file: None | str | Unset
        if isinstance(self.module_file, Unset):
            module_file = UNSET
        else:
            module_file = self.module_file

        module_path = self.module_path

        module_type: None | str | Unset
        if isinstance(self.module_type, Unset):
            module_type = UNSET
        else:
            module_type = self.module_type

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        platforms: list[str] | Unset = UNSET
        if not isinstance(self.platforms, Unset):
            platforms = self.platforms

        rank: int | None | Unset
        if isinstance(self.rank, Unset):
            rank = UNSET
        else:
            rank = self.rank

        rank_label: None | str | Unset
        if isinstance(self.rank_label, Unset):
            rank_label = UNSET
        else:
            rank_label = self.rank_label

        ref_name: None | str | Unset
        if isinstance(self.ref_name, Unset):
            ref_name = UNSET
        else:
            ref_name = self.ref_name

        references: list[str] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = self.references

        reliability: list[str] | Unset = UNSET
        if not isinstance(self.reliability, Unset):
            reliability = self.reliability

        retrieved_at = self.retrieved_at

        side_effects: list[str] | Unset = UNSET
        if not isinstance(self.side_effects, Unset):
            side_effects = self.side_effects

        source = self.source

        source_url = self.source_url

        stability: list[str] | Unset = UNSET
        if not isinstance(self.stability, Unset):
            stability = self.stability

        targets: list[str] | Unset = UNSET
        if not isinstance(self.targets, Unset):
            targets = self.targets

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if archs is not UNSET:
            field_dict["archs"] = archs
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if disclosure_date is not UNSET:
            field_dict["disclosure_date"] = disclosure_date
        if is_scada is not UNSET:
            field_dict["is_scada"] = is_scada
        if licence is not UNSET:
            field_dict["licence"] = licence
        if licence_url is not UNSET:
            field_dict["licence_url"] = licence_url
        if modified is not UNSET:
            field_dict["modified"] = modified
        if module_file is not UNSET:
            field_dict["module_file"] = module_file
        if module_path is not UNSET:
            field_dict["module_path"] = module_path
        if module_type is not UNSET:
            field_dict["module_type"] = module_type
        if name is not UNSET:
            field_dict["name"] = name
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if rank is not UNSET:
            field_dict["rank"] = rank
        if rank_label is not UNSET:
            field_dict["rank_label"] = rank_label
        if ref_name is not UNSET:
            field_dict["ref_name"] = ref_name
        if references is not UNSET:
            field_dict["references"] = references
        if reliability is not UNSET:
            field_dict["reliability"] = reliability
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if side_effects is not UNSET:
            field_dict["side_effects"] = side_effects
        if source is not UNSET:
            field_dict["source"] = source
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if stability is not UNSET:
            field_dict["stability"] = stability
        if targets is not UNSET:
            field_dict["targets"] = targets

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        archs = cast(list[str], d.pop("archs", UNSET))

        attribution = d.pop("attribution", UNSET)

        def _parse_disclosure_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        disclosure_date = _parse_disclosure_date(d.pop("disclosure_date", UNSET))

        is_scada = d.pop("is_scada", UNSET)

        licence = d.pop("licence", UNSET)

        licence_url = d.pop("licence_url", UNSET)

        def _parse_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified = _parse_modified(d.pop("modified", UNSET))

        def _parse_module_file(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        module_file = _parse_module_file(d.pop("module_file", UNSET))

        module_path = d.pop("module_path", UNSET)

        def _parse_module_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        module_type = _parse_module_type(d.pop("module_type", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        platforms = cast(list[str], d.pop("platforms", UNSET))

        def _parse_rank(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rank = _parse_rank(d.pop("rank", UNSET))

        def _parse_rank_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        rank_label = _parse_rank_label(d.pop("rank_label", UNSET))

        def _parse_ref_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ref_name = _parse_ref_name(d.pop("ref_name", UNSET))

        references = cast(list[str], d.pop("references", UNSET))

        reliability = cast(list[str], d.pop("reliability", UNSET))

        retrieved_at = d.pop("retrieved_at", UNSET)

        side_effects = cast(list[str], d.pop("side_effects", UNSET))

        source = d.pop("source", UNSET)

        source_url = d.pop("source_url", UNSET)

        stability = cast(list[str], d.pop("stability", UNSET))

        targets = cast(list[str], d.pop("targets", UNSET))

        metasploit_module = cls(
            archs=archs,
            attribution=attribution,
            disclosure_date=disclosure_date,
            is_scada=is_scada,
            licence=licence,
            licence_url=licence_url,
            modified=modified,
            module_file=module_file,
            module_path=module_path,
            module_type=module_type,
            name=name,
            platforms=platforms,
            rank=rank,
            rank_label=rank_label,
            ref_name=ref_name,
            references=references,
            reliability=reliability,
            retrieved_at=retrieved_at,
            side_effects=side_effects,
            source=source,
            source_url=source_url,
            stability=stability,
            targets=targets,
        )

        metasploit_module.additional_properties = d
        return metasploit_module

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
