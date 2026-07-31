from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.technique_detail import TechniqueDetail


T = TypeVar("T", bound="SoftwareDetail")


@_attrs_define
class SoftwareDetail:
    """Malware or tool profile with techniques and associated threat groups.

    Attributes:
        software_id (str): ATT&CK software ID (e.g. S0154)
        aliases (list[str] | Unset): Alternative names
        capabilities (list[str] | Unset): STIX malware capabilities (e.g. 'persistence', 'exfiltration'); empty for tool
            objects
        contributors (list[str] | Unset): Contributors listed in x_mitre_contributors
        deprecated (bool | Unset): True if MITRE marked this software deprecated Default: False.
        description (None | str | Unset): Software description and capabilities
        groups (list[str] | Unset): Threat groups known to use this software
        name (None | str | Unset): Software name (e.g. 'Cobalt Strike')
        platforms (list[str] | Unset): Targeted platforms
        revoked (bool | Unset): True if MITRE has revoked this software Default: False.
        software_type (None | str | Unset): Type: malware or tool
        techniques (list[str | TechniqueDetail] | Unset): ATT&CK techniques associated with this software
        url (None | str | Unset): Reference URL for full software details
        version (None | str | Unset): MITRE object version (x_mitre_version)
    """

    software_id: str
    aliases: list[str] | Unset = UNSET
    capabilities: list[str] | Unset = UNSET
    contributors: list[str] | Unset = UNSET
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    groups: list[str] | Unset = UNSET
    name: None | str | Unset = UNSET
    platforms: list[str] | Unset = UNSET
    revoked: bool | Unset = False
    software_type: None | str | Unset = UNSET
    techniques: list[str | TechniqueDetail] | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.technique_detail import TechniqueDetail

        software_id = self.software_id

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        capabilities: list[str] | Unset = UNSET
        if not isinstance(self.capabilities, Unset):
            capabilities = self.capabilities

        contributors: list[str] | Unset = UNSET
        if not isinstance(self.contributors, Unset):
            contributors = self.contributors

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        groups: list[str] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        platforms: list[str] | Unset = UNSET
        if not isinstance(self.platforms, Unset):
            platforms = self.platforms

        revoked = self.revoked

        software_type: None | str | Unset
        if isinstance(self.software_type, Unset):
            software_type = UNSET
        else:
            software_type = self.software_type

        techniques: list[dict[str, Any] | str] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = []
            for techniques_item_data in self.techniques:
                techniques_item: dict[str, Any] | str
                if isinstance(techniques_item_data, TechniqueDetail):
                    techniques_item = techniques_item_data.to_dict()
                else:
                    techniques_item = techniques_item_data
                techniques.append(techniques_item)

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
                "software_id": software_id,
            }
        )
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if capabilities is not UNSET:
            field_dict["capabilities"] = capabilities
        if contributors is not UNSET:
            field_dict["contributors"] = contributors
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if groups is not UNSET:
            field_dict["groups"] = groups
        if name is not UNSET:
            field_dict["name"] = name
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if software_type is not UNSET:
            field_dict["software_type"] = software_type
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if url is not UNSET:
            field_dict["url"] = url
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.technique_detail import TechniqueDetail

        d = dict(src_dict)
        software_id = d.pop("software_id")

        aliases = cast(list[str], d.pop("aliases", UNSET))

        capabilities = cast(list[str], d.pop("capabilities", UNSET))

        contributors = cast(list[str], d.pop("contributors", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        groups = cast(list[str], d.pop("groups", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        platforms = cast(list[str], d.pop("platforms", UNSET))

        revoked = d.pop("revoked", UNSET)

        def _parse_software_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        software_type = _parse_software_type(d.pop("software_type", UNSET))

        _techniques = d.pop("techniques", UNSET)
        techniques: list[str | TechniqueDetail] | Unset = UNSET
        if _techniques is not UNSET:
            techniques = []
            for techniques_item_data in _techniques:

                def _parse_techniques_item(data: object) -> str | TechniqueDetail:
                    try:
                        if not isinstance(data, dict):
                            raise TypeError()
                        techniques_item_type_1 = TechniqueDetail.from_dict(data)

                        return techniques_item_type_1
                    except (TypeError, ValueError, AttributeError, KeyError):
                        pass
                    return cast(str | TechniqueDetail, data)

                techniques_item = _parse_techniques_item(techniques_item_data)

                techniques.append(techniques_item)

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

        software_detail = cls(
            software_id=software_id,
            aliases=aliases,
            capabilities=capabilities,
            contributors=contributors,
            deprecated=deprecated,
            description=description,
            groups=groups,
            name=name,
            platforms=platforms,
            revoked=revoked,
            software_type=software_type,
            techniques=techniques,
            url=url,
            version=version,
        )

        software_detail.additional_properties = d
        return software_detail

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
