from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.related_asset_class import RelatedAssetClass


T = TypeVar("T", bound="AssetClass")


@_attrs_define
class AssetClass:
    """An ICS asset class a technique targets (PLC, HMI, RTU, Safety Controller, …).

    Attributes:
        asset_id (str | Unset): MITRE ICS asset id (e.g. 'A0001') Default: ''.
        description (str | Unset): What this asset class is Default: ''.
        name (str | Unset): Asset class name Default: ''.
        platforms (list[str] | Unset): Platforms this asset class runs on (x_mitre_platforms) — carried by all 18 ICS
            asset objects in 8 distinct combinations, the field that says whether an exposure is a Windows workstation or an
            embedded controller
        related_asset_details (list[RelatedAssetClass] | Unset): The same related asset classes with MITRE's own
            description and sectors for each — the part that says WHY the class is related
        related_assets (list[str] | Unset): Related asset classes named by MITRE (x_mitre_related_assets) — names only
        sectors (list[str] | Unset): Sectors this asset class appears in (x_mitre_sectors)
        stix_id (str | Unset): STIX object id Default: ''.
        technique_ids (list[str] | Unset): ICS techniques whose `targets` edge points at this asset class — the inverse
            of the technique→asset direction, so the ATT&CK ICS asset graph is traversable both ways. Resolved from the
            corpus's own `targets` relationships.
        url (str | Unset): Reference URL Default: ''.
    """

    asset_id: str | Unset = ""
    description: str | Unset = ""
    name: str | Unset = ""
    platforms: list[str] | Unset = UNSET
    related_asset_details: list[RelatedAssetClass] | Unset = UNSET
    related_assets: list[str] | Unset = UNSET
    sectors: list[str] | Unset = UNSET
    stix_id: str | Unset = ""
    technique_ids: list[str] | Unset = UNSET
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.related_asset_class import RelatedAssetClass  # noqa: PLC0415

        asset_id = self.asset_id

        description = self.description

        name = self.name

        platforms: list[str] | Unset = UNSET
        if not isinstance(self.platforms, Unset):
            platforms = self.platforms

        related_asset_details: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.related_asset_details, Unset):
            related_asset_details = []
            for related_asset_details_item_data in self.related_asset_details:
                related_asset_details_item = related_asset_details_item_data.to_dict()
                related_asset_details.append(related_asset_details_item)

        related_assets: list[str] | Unset = UNSET
        if not isinstance(self.related_assets, Unset):
            related_assets = self.related_assets

        sectors: list[str] | Unset = UNSET
        if not isinstance(self.sectors, Unset):
            sectors = self.sectors

        stix_id = self.stix_id

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if description is not UNSET:
            field_dict["description"] = description
        if name is not UNSET:
            field_dict["name"] = name
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if related_asset_details is not UNSET:
            field_dict["related_asset_details"] = related_asset_details
        if related_assets is not UNSET:
            field_dict["related_assets"] = related_assets
        if sectors is not UNSET:
            field_dict["sectors"] = sectors
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.related_asset_class import RelatedAssetClass  # noqa: PLC0415

        d = dict(src_dict)
        asset_id = d.pop("asset_id", UNSET)

        description = d.pop("description", UNSET)

        name = d.pop("name", UNSET)

        platforms = cast(list[str], d.pop("platforms", UNSET))

        _related_asset_details = d.pop("related_asset_details", UNSET)
        related_asset_details: list[RelatedAssetClass] | Unset = UNSET
        if _related_asset_details is not UNSET:
            related_asset_details = []
            for related_asset_details_item_data in _related_asset_details:
                related_asset_details_item = RelatedAssetClass.from_dict(related_asset_details_item_data)

                related_asset_details.append(related_asset_details_item)

        related_assets = cast(list[str], d.pop("related_assets", UNSET))

        sectors = cast(list[str], d.pop("sectors", UNSET))

        stix_id = d.pop("stix_id", UNSET)

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        url = d.pop("url", UNSET)

        asset_class = cls(
            asset_id=asset_id,
            description=description,
            name=name,
            platforms=platforms,
            related_asset_details=related_asset_details,
            related_assets=related_assets,
            sectors=sectors,
            stix_id=stix_id,
            technique_ids=technique_ids,
            url=url,
        )

        asset_class.additional_properties = d
        return asset_class

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
