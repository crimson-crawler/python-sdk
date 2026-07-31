from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.technique_detail import TechniqueDetail


T = TypeVar("T", bound="CampaignDetail")


@_attrs_define
class CampaignDetail:
    """Threat campaign profile with linked groups and techniques.

    Attributes:
        campaign_id (str): ATT&CK campaign ID (e.g. C0028)
        aliases (list[str] | Unset): Alternative campaign names
        contributors (list[str] | Unset): Contributors listed in x_mitre_contributors
        deprecated (bool | Unset): True if MITRE marked this campaign deprecated Default: False.
        description (None | str | Unset): Campaign description and objectives
        first_seen (None | str | Unset): Earliest known activity date
        groups (list[str] | Unset): Threat groups attributed to this campaign
        last_seen (None | str | Unset): Most recent known activity date
        name (None | str | Unset): Campaign name
        revoked (bool | Unset): True if MITRE has revoked this campaign Default: False.
        techniques (list[str | TechniqueDetail] | Unset): ATT&CK techniques used in this campaign
        url (None | str | Unset): Reference URL for full campaign details
        version (None | str | Unset): MITRE object version (x_mitre_version)
    """

    campaign_id: str
    aliases: list[str] | Unset = UNSET
    contributors: list[str] | Unset = UNSET
    deprecated: bool | Unset = False
    description: None | str | Unset = UNSET
    first_seen: None | str | Unset = UNSET
    groups: list[str] | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    name: None | str | Unset = UNSET
    revoked: bool | Unset = False
    techniques: list[str | TechniqueDetail] | Unset = UNSET
    url: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.technique_detail import TechniqueDetail

        campaign_id = self.campaign_id

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        contributors: list[str] | Unset = UNSET
        if not isinstance(self.contributors, Unset):
            contributors = self.contributors

        deprecated = self.deprecated

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        groups: list[str] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        revoked = self.revoked

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
                "campaign_id": campaign_id,
            }
        )
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if contributors is not UNSET:
            field_dict["contributors"] = contributors
        if deprecated is not UNSET:
            field_dict["deprecated"] = deprecated
        if description is not UNSET:
            field_dict["description"] = description
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if groups is not UNSET:
            field_dict["groups"] = groups
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if name is not UNSET:
            field_dict["name"] = name
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
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
        campaign_id = d.pop("campaign_id")

        aliases = cast(list[str], d.pop("aliases", UNSET))

        contributors = cast(list[str], d.pop("contributors", UNSET))

        deprecated = d.pop("deprecated", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_first_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        groups = cast(list[str], d.pop("groups", UNSET))

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        revoked = d.pop("revoked", UNSET)

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

        campaign_detail = cls(
            campaign_id=campaign_id,
            aliases=aliases,
            contributors=contributors,
            deprecated=deprecated,
            description=description,
            first_seen=first_seen,
            groups=groups,
            last_seen=last_seen,
            name=name,
            revoked=revoked,
            techniques=techniques,
            url=url,
            version=version,
        )

        campaign_detail.additional_properties = d
        return campaign_detail

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
