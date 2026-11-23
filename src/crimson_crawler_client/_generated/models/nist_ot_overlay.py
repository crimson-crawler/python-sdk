from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.nist_ot_overlay_baselines_item import NistOTOverlayBaselinesItem
from ..types import UNSET, Unset

T = TypeVar("T", bound="NistOTOverlay")


@_attrs_define
class NistOTOverlay:
    """NIST SP 800-82r3 Appendix F OT-specific control guidance.

    Attributes:
        baselines (list[NistOTOverlayBaselinesItem]): OT security baselines selecting this control or enhancement
        ot_discussion (None | str): NIST OT discussion, limited to its first 512 characters; null when none is provided
        source_url (str): NIST publication URL
        source (Literal['nist-sp-800-82r3'] | Unset): Overlay source Default: 'nist-sp-800-82r3'.
    """

    baselines: list[NistOTOverlayBaselinesItem]
    ot_discussion: None | str
    source_url: str
    source: Literal["nist-sp-800-82r3"] | Unset = "nist-sp-800-82r3"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        baselines = []
        for baselines_item_data in self.baselines:
            baselines_item = baselines_item_data.value
            baselines.append(baselines_item)

        ot_discussion: None | str
        ot_discussion = self.ot_discussion

        source_url = self.source_url

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "baselines": baselines,
                "ot_discussion": ot_discussion,
                "source_url": source_url,
            }
        )
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        baselines = []
        _baselines = d.pop("baselines")
        for baselines_item_data in _baselines:
            baselines_item = NistOTOverlayBaselinesItem(baselines_item_data)

            baselines.append(baselines_item)

        def _parse_ot_discussion(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        ot_discussion = _parse_ot_discussion(d.pop("ot_discussion"))

        source_url = d.pop("source_url")

        source = cast(Literal["nist-sp-800-82r3"] | Unset, d.pop("source", UNSET))
        if source != "nist-sp-800-82r3" and not isinstance(source, Unset):
            raise ValueError(f"source must match const 'nist-sp-800-82r3', got '{source}'")

        nist_ot_overlay = cls(
            baselines=baselines,
            ot_discussion=ot_discussion,
            source_url=source_url,
            source=source,
        )

        nist_ot_overlay.additional_properties = d
        return nist_ot_overlay

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
