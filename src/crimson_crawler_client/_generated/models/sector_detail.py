from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.group_detail import GroupDetail
    from ..models.sector_detail_groups_item_type_2 import SectorDetailGroupsItemType2
    from ..models.technique_detail import TechniqueDetail


T = TypeVar("T", bound="SectorDetail")


@_attrs_define
class SectorDetail:
    """Industry sector threat profile - groups and techniques targeting this sector.

    Attributes:
        aliases (list[str] | Unset): Known aliases for this sector
        description (None | str | Unset): Sector threat landscape description
        groups (list[GroupDetail | SectorDetailGroupsItemType2 | str] | Unset): Threat groups known to target this
            sector
        identity_class (str | Unset): STIX identity_class (e.g. 'class') Default: ''.
        name (None | str | Unset): Sector name (e.g. 'Financial Services')
        sector_id (str | Unset): Sector identifier Default: ''.
        sectors (list[str] | Unset): Sub-sector list (NACE / NAICS-style breakdown)
        stix_id (str | Unset): STIX object identifier Default: ''.
        techniques (list[str | TechniqueDetail] | Unset): ATT&CK techniques used against this sector
    """

    aliases: list[str] | Unset = UNSET
    description: None | str | Unset = UNSET
    groups: list[GroupDetail | SectorDetailGroupsItemType2 | str] | Unset = UNSET
    identity_class: str | Unset = ""
    name: None | str | Unset = UNSET
    sector_id: str | Unset = ""
    sectors: list[str] | Unset = UNSET
    stix_id: str | Unset = ""
    techniques: list[str | TechniqueDetail] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.group_detail import GroupDetail
        from ..models.sector_detail_groups_item_type_2 import SectorDetailGroupsItemType2
        from ..models.technique_detail import TechniqueDetail

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        groups: list[dict[str, Any] | str] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = []
            for groups_item_data in self.groups:
                groups_item: dict[str, Any] | str
                if isinstance(groups_item_data, GroupDetail):
                    groups_item = groups_item_data.to_dict()
                elif isinstance(groups_item_data, SectorDetailGroupsItemType2):
                    groups_item = groups_item_data.to_dict()
                else:
                    groups_item = groups_item_data
                groups.append(groups_item)

        identity_class = self.identity_class

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        sector_id = self.sector_id

        sectors: list[str] | Unset = UNSET
        if not isinstance(self.sectors, Unset):
            sectors = self.sectors

        stix_id = self.stix_id

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

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if description is not UNSET:
            field_dict["description"] = description
        if groups is not UNSET:
            field_dict["groups"] = groups
        if identity_class is not UNSET:
            field_dict["identity_class"] = identity_class
        if name is not UNSET:
            field_dict["name"] = name
        if sector_id is not UNSET:
            field_dict["sector_id"] = sector_id
        if sectors is not UNSET:
            field_dict["sectors"] = sectors
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if techniques is not UNSET:
            field_dict["techniques"] = techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.group_detail import GroupDetail
        from ..models.sector_detail_groups_item_type_2 import SectorDetailGroupsItemType2
        from ..models.technique_detail import TechniqueDetail

        d = dict(src_dict)
        aliases = cast(list[str], d.pop("aliases", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        _groups = d.pop("groups", UNSET)
        groups: list[GroupDetail | SectorDetailGroupsItemType2 | str] | Unset = UNSET
        if _groups is not UNSET:
            groups = []
            for groups_item_data in _groups:

                def _parse_groups_item(data: object) -> GroupDetail | SectorDetailGroupsItemType2 | str:
                    try:
                        if not isinstance(data, dict):
                            raise TypeError()
                        groups_item_type_1 = GroupDetail.from_dict(data)

                        return groups_item_type_1
                    except (TypeError, ValueError, AttributeError, KeyError):
                        pass
                    try:
                        if not isinstance(data, dict):
                            raise TypeError()
                        groups_item_type_2 = SectorDetailGroupsItemType2.from_dict(data)

                        return groups_item_type_2
                    except (TypeError, ValueError, AttributeError, KeyError):
                        pass
                    return cast(GroupDetail | SectorDetailGroupsItemType2 | str, data)

                groups_item = _parse_groups_item(groups_item_data)

                groups.append(groups_item)

        identity_class = d.pop("identity_class", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        sector_id = d.pop("sector_id", UNSET)

        sectors = cast(list[str], d.pop("sectors", UNSET))

        stix_id = d.pop("stix_id", UNSET)

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

        sector_detail = cls(
            aliases=aliases,
            description=description,
            groups=groups,
            identity_class=identity_class,
            name=name,
            sector_id=sector_id,
            sectors=sectors,
            stix_id=stix_id,
            techniques=techniques,
        )

        sector_detail.additional_properties = d
        return sector_detail

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
