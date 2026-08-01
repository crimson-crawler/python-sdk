from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.batch_campaign_item_framework import BatchCampaignItemFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchCampaignItem")


@_attrs_define
class BatchCampaignItem:
    """Batch item: enrich a threat campaign.

    Attributes:
        campaign_id (None | str | Unset): ATT&CK campaign ID for direct lookup (e.g. C0028)
        framework (BatchCampaignItemFramework | Unset): ATT&CK framework: enterprise, ics, or mobile Default:
            BatchCampaignItemFramework.ENTERPRISE.
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: cves,
            defend, details, detections, groups, knowledgebase, mitigations, navigator, nist_controls, software, summary,
            techniques, tie, web, web_scrape.
        search (None | str | Unset): Text query to search campaigns by name or description
        type_ (Literal['campaign'] | Unset): Selects campaign enrichment for this batch item Default: 'campaign'.
    """

    campaign_id: None | str | Unset = UNSET
    framework: BatchCampaignItemFramework | Unset = BatchCampaignItemFramework.ENTERPRISE
    include: list[str] | Unset = UNSET
    search: None | str | Unset = UNSET
    type_: Literal["campaign"] | Unset = "campaign"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        campaign_id: None | str | Unset
        if isinstance(self.campaign_id, Unset):
            campaign_id = UNSET
        else:
            campaign_id = self.campaign_id

        framework: str | Unset = UNSET
        if not isinstance(self.framework, Unset):
            framework = self.framework.value

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        search: None | str | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        else:
            search = self.search

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if campaign_id is not UNSET:
            field_dict["campaign_id"] = campaign_id
        if framework is not UNSET:
            field_dict["framework"] = framework
        if include is not UNSET:
            field_dict["include"] = include
        if search is not UNSET:
            field_dict["search"] = search
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_campaign_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        campaign_id = _parse_campaign_id(d.pop("campaign_id", UNSET))

        _framework = d.pop("framework", UNSET)
        framework: BatchCampaignItemFramework | Unset
        if isinstance(_framework, Unset):
            framework = UNSET
        else:
            framework = BatchCampaignItemFramework(_framework)

        include = cast(list[str], d.pop("include", UNSET))

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        type_ = cast(Literal["campaign"] | Unset, d.pop("type", UNSET))
        if type_ != "campaign" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'campaign', got '{type_}'")

        batch_campaign_item = cls(
            campaign_id=campaign_id,
            framework=framework,
            include=include,
            search=search,
            type_=type_,
        )

        batch_campaign_item.additional_properties = d
        return batch_campaign_item

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
