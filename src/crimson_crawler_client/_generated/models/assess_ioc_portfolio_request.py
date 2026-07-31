from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.assess_ioc_portfolio_request_indicators_item import AssessIOCPortfolioRequestIndicatorsItem


T = TypeVar("T", bound="AssessIOCPortfolioRequest")


@_attrs_define
class AssessIOCPortfolioRequest:
    """Assess the combined threat picture across multiple indicators of compromise.

    Attributes:
        indicators (list[AssessIOCPortfolioRequestIndicatorsItem]): List of IOCs, each with 'value' and 'type' keys
        include (list[str] | Unset): Assessment layers to include. Replaces the default list. Allowed values: campaigns,
            defend, detections, galaxies, groups, misp_attributes, mitigations, nist_controls, sightings, software, summary,
            techniques, tie, warninglist.
    """

    indicators: list[AssessIOCPortfolioRequestIndicatorsItem]
    include: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.assess_ioc_portfolio_request_indicators_item import AssessIOCPortfolioRequestIndicatorsItem

        indicators = []
        for indicators_item_data in self.indicators:
            indicators_item = indicators_item_data.to_dict()
            indicators.append(indicators_item)

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "indicators": indicators,
            }
        )
        if include is not UNSET:
            field_dict["include"] = include

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.assess_ioc_portfolio_request_indicators_item import AssessIOCPortfolioRequestIndicatorsItem

        d = dict(src_dict)
        indicators = []
        _indicators = d.pop("indicators")
        for indicators_item_data in _indicators:
            indicators_item = AssessIOCPortfolioRequestIndicatorsItem.from_dict(indicators_item_data)

            indicators.append(indicators_item)

        include = cast(list[str], d.pop("include", UNSET))

        assess_ioc_portfolio_request = cls(
            indicators=indicators,
            include=include,
        )

        assess_ioc_portfolio_request.additional_properties = d
        return assess_ioc_portfolio_request

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
