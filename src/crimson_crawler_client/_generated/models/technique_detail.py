from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.technique_detail_kill_chain_phases_item import TechniqueDetailKillChainPhasesItem


T = TypeVar("T", bound="TechniqueDetail")


@_attrs_define
class TechniqueDetail:
    """MITRE ATT&CK technique - a specific adversary behavior mapped to tactics.

    Attributes:
        technique_id (str): ATT&CK technique ID (e.g. T1190)
        aliases (list[str] | Unset): Alternative technique names
        contributors (list[str] | Unset): Technique contributors from x_mitre_contributors
        data_sources (list[str] | Unset): Data sources for detecting this technique
        deprecated (bool | Unset): True if MITRE marked this technique deprecated (x_mitre_deprecated) Default: False.
        description (None | str | Unset): Detailed technique description
        detection (None | str | Unset): Detection guidance from ATT&CK
        domains (list[str] | Unset): ATT&CK domains (enterprise-attack, ics-attack, mobile-attack)
        is_subtechnique (bool | Unset): Whether this is a sub-technique (e.g. T1059.001) Default: False.
        kill_chain_phases (list[TechniqueDetailKillChainPhasesItem] | Unset): Ordered kill-chain phases ({phase_name,
            tactic_order}) for attack-path sequencing
        name (None | str | Unset): Technique name (e.g. 'Exploit Public-Facing Application')
        permissions_required (list[str] | Unset): Permissions required to execute this technique
        platforms (list[str] | Unset): Applicable platforms (e.g. ['Windows', 'Linux', 'macOS'])
        remote_support (bool | None | Unset): Whether the technique supports remote execution
        revoked (bool | Unset): True if MITRE has revoked this technique Default: False.
        stix_id (None | str | Unset): Unique object identifier for cross-referencing
        tactics (list[str] | Unset): ATT&CK tactics this technique belongs to (e.g. ['initial-access'])
        url (None | str | Unset): Reference URL for full technique details
        version (None | str | Unset): MITRE object version (x_mitre_version)
    """

    technique_id: str
    aliases: list[str] | Unset = UNSET
    contributors: list[str] | Unset = UNSET
    data_sources: list[str] | Unset = UNSET
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    detection: None | str | Unset = UNSET
    domains: list[str] | Unset = UNSET
    is_subtechnique: bool | Unset = False
    kill_chain_phases: list[TechniqueDetailKillChainPhasesItem] | Unset = UNSET
    name: None | str | Unset = UNSET
    permissions_required: list[str] | Unset = UNSET
    platforms: list[str] | Unset = UNSET
    remote_support: bool | None | Unset = UNSET
    revoked: bool | Unset = False
    stix_id: None | str | Unset = UNSET
    tactics: list[str] | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.technique_detail_kill_chain_phases_item import TechniqueDetailKillChainPhasesItem

        technique_id = self.technique_id

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        contributors: list[str] | Unset = UNSET
        if not isinstance(self.contributors, Unset):
            contributors = self.contributors

        data_sources: list[str] | Unset = UNSET
        if not isinstance(self.data_sources, Unset):
            data_sources = self.data_sources

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        detection: None | str | Unset
        if isinstance(self.detection, Unset):
            detection = UNSET
        else:
            detection = self.detection

        domains: list[str] | Unset = UNSET
        if not isinstance(self.domains, Unset):
            domains = self.domains

        is_subtechnique = self.is_subtechnique

        kill_chain_phases: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.kill_chain_phases, Unset):
            kill_chain_phases = []
            for kill_chain_phases_item_data in self.kill_chain_phases:
                kill_chain_phases_item = kill_chain_phases_item_data.to_dict()
                kill_chain_phases.append(kill_chain_phases_item)

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        permissions_required: list[str] | Unset = UNSET
        if not isinstance(self.permissions_required, Unset):
            permissions_required = self.permissions_required

        platforms: list[str] | Unset = UNSET
        if not isinstance(self.platforms, Unset):
            platforms = self.platforms

        remote_support: bool | None | Unset
        if isinstance(self.remote_support, Unset):
            remote_support = UNSET
        else:
            remote_support = self.remote_support

        revoked = self.revoked

        stix_id: None | str | Unset
        if isinstance(self.stix_id, Unset):
            stix_id = UNSET
        else:
            stix_id = self.stix_id

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique_id": technique_id,
            }
        )
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if contributors is not UNSET:
            field_dict["contributors"] = contributors
        if data_sources is not UNSET:
            field_dict["data_sources"] = data_sources
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if detection is not UNSET:
            field_dict["detection"] = detection
        if domains is not UNSET:
            field_dict["domains"] = domains
        if is_subtechnique is not UNSET:
            field_dict["is_subtechnique"] = is_subtechnique
        if kill_chain_phases is not UNSET:
            field_dict["kill_chain_phases"] = kill_chain_phases
        if name is not UNSET:
            field_dict["name"] = name
        if permissions_required is not UNSET:
            field_dict["permissions_required"] = permissions_required
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if remote_support is not UNSET:
            field_dict["remote_support"] = remote_support
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if tactics is not UNSET:
            field_dict["tactics"] = tactics
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.technique_detail_kill_chain_phases_item import TechniqueDetailKillChainPhasesItem

        d = dict(src_dict)
        technique_id = d.pop("technique_id")

        aliases = cast(list[str], d.pop("aliases", UNSET))

        contributors = cast(list[str], d.pop("contributors", UNSET))

        data_sources = cast(list[str], d.pop("data_sources", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_detection(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detection = _parse_detection(d.pop("detection", UNSET))

        domains = cast(list[str], d.pop("domains", UNSET))

        is_subtechnique = d.pop("is_subtechnique", UNSET)

        _kill_chain_phases = d.pop("kill_chain_phases", UNSET)
        kill_chain_phases: list[TechniqueDetailKillChainPhasesItem] | Unset = UNSET
        if _kill_chain_phases is not UNSET:
            kill_chain_phases = []
            for kill_chain_phases_item_data in _kill_chain_phases:
                kill_chain_phases_item = TechniqueDetailKillChainPhasesItem.from_dict(kill_chain_phases_item_data)

                kill_chain_phases.append(kill_chain_phases_item)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        permissions_required = cast(list[str], d.pop("permissions_required", UNSET))

        platforms = cast(list[str], d.pop("platforms", UNSET))

        def _parse_remote_support(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        remote_support = _parse_remote_support(d.pop("remote_support", UNSET))

        revoked = d.pop("revoked", UNSET)

        def _parse_stix_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stix_id = _parse_stix_id(d.pop("stix_id", UNSET))

        tactics = cast(list[str], d.pop("tactics", UNSET))

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        technique_detail = cls(
            technique_id=technique_id,
            aliases=aliases,
            contributors=contributors,
            data_sources=data_sources,
            deprecated=deprecated,
            description=description,
            detection=detection,
            domains=domains,
            is_subtechnique=is_subtechnique,
            kill_chain_phases=kill_chain_phases,
            name=name,
            permissions_required=permissions_required,
            platforms=platforms,
            remote_support=remote_support,
            revoked=revoked,
            stix_id=stix_id,
            tactics=tactics,
            url=url,
            version=version,
        )

        technique_detail.additional_properties = d
        return technique_detail

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
