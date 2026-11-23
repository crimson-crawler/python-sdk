from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.analytic_detail import AnalyticDetail


T = TypeVar("T", bound="DetectionStrategy")


@_attrs_define
class DetectionStrategy:
    """An ATT&CK v18 detection strategy for a technique, with the analytics that carry its logic.

    v18 replaced the flat detection string with these; the strategy names the approach and its
    analytics hold the actual detection logic.

        Attributes:
            analytics (list[str] | Unset): Detection analytics for this strategy — the detection logic
            analytics_detail (list[AnalyticDetail] | Unset): Per-analytic tunables and log sources. Opt-in via
                include=['analytic_details']: the mutable-element + log-source-reference pair is ~91% of a technique body (2,174
                and 2,255 of 2,311 enterprise analytics carry them), so it is requested rather than imposed.
            name (str | Unset): Detection strategy name Default: ''.
    """

    analytics: list[str] | Unset = UNSET
    analytics_detail: list[AnalyticDetail] | Unset = UNSET
    name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.analytic_detail import AnalyticDetail  # noqa: PLC0415

        analytics: list[str] | Unset = UNSET
        if not isinstance(self.analytics, Unset):
            analytics = self.analytics

        analytics_detail: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.analytics_detail, Unset):
            analytics_detail = []
            for analytics_detail_item_data in self.analytics_detail:
                analytics_detail_item = analytics_detail_item_data.to_dict()
                analytics_detail.append(analytics_detail_item)

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if analytics is not UNSET:
            field_dict["analytics"] = analytics
        if analytics_detail is not UNSET:
            field_dict["analytics_detail"] = analytics_detail
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.analytic_detail import AnalyticDetail  # noqa: PLC0415

        d = dict(src_dict)
        analytics = cast(list[str], d.pop("analytics", UNSET))

        _analytics_detail = d.pop("analytics_detail", UNSET)
        analytics_detail: list[AnalyticDetail] | Unset = UNSET
        if _analytics_detail is not UNSET:
            analytics_detail = []
            for analytics_detail_item_data in _analytics_detail:
                analytics_detail_item = AnalyticDetail.from_dict(analytics_detail_item_data)

                analytics_detail.append(analytics_detail_item)

        name = d.pop("name", UNSET)

        detection_strategy = cls(
            analytics=analytics,
            analytics_detail=analytics_detail,
            name=name,
        )

        detection_strategy.additional_properties = d
        return detection_strategy

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
