from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.detection_strategy import DetectionStrategy
    from ..models.log_source_group import LogSourceGroup


T = TypeVar("T", bound="InventoryTechniqueProfile")


@_attrs_define
class InventoryTechniqueProfile:
    """One ATT&CK technique linked to the inventory's CVEs, described once for the whole result.

    Attributes:
        technique_id (str): ATT&CK technique id
        cve_count (int | Unset): Distinct inventory CVEs linked to this technique Default: 0.
        detection_strategies (list[DetectionStrategy] | Unset): ATT&CK v18 detection strategies, each with its analytics
        log_sources (list[LogSourceGroup] | Unset): Log sources that observe it, grouped per source
        mitigation_ids (list[str] | Unset): Mitigations (see `mitigation_catalog`) that address it
        name (None | str | Unset): Technique name
        platforms (list[str] | Unset): Platforms it applies to
        tactics (list[str] | Unset): Tactics the technique serves
    """

    technique_id: str
    cve_count: int | Unset = 0
    detection_strategies: list[DetectionStrategy] | Unset = UNSET
    log_sources: list[LogSourceGroup] | Unset = UNSET
    mitigation_ids: list[str] | Unset = UNSET
    name: None | str | Unset = UNSET
    platforms: list[str] | Unset = UNSET
    tactics: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.detection_strategy import DetectionStrategy  # noqa: PLC0415
        from ..models.log_source_group import LogSourceGroup  # noqa: PLC0415

        technique_id = self.technique_id

        cve_count = self.cve_count

        detection_strategies: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.detection_strategies, Unset):
            detection_strategies = []
            for detection_strategies_item_data in self.detection_strategies:
                detection_strategies_item = detection_strategies_item_data.to_dict()
                detection_strategies.append(detection_strategies_item)

        log_sources: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.log_sources, Unset):
            log_sources = []
            for log_sources_item_data in self.log_sources:
                log_sources_item = log_sources_item_data.to_dict()
                log_sources.append(log_sources_item)

        mitigation_ids: list[str] | Unset = UNSET
        if not isinstance(self.mitigation_ids, Unset):
            mitigation_ids = self.mitigation_ids

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        platforms: list[str] | Unset = UNSET
        if not isinstance(self.platforms, Unset):
            platforms = self.platforms

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique_id": technique_id,
            }
        )
        if cve_count is not UNSET:
            field_dict["cve_count"] = cve_count
        if detection_strategies is not UNSET:
            field_dict["detection_strategies"] = detection_strategies
        if log_sources is not UNSET:
            field_dict["log_sources"] = log_sources
        if mitigation_ids is not UNSET:
            field_dict["mitigation_ids"] = mitigation_ids
        if name is not UNSET:
            field_dict["name"] = name
        if platforms is not UNSET:
            field_dict["platforms"] = platforms
        if tactics is not UNSET:
            field_dict["tactics"] = tactics

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.detection_strategy import DetectionStrategy  # noqa: PLC0415
        from ..models.log_source_group import LogSourceGroup  # noqa: PLC0415

        d = dict(src_dict)
        technique_id = d.pop("technique_id")

        cve_count = d.pop("cve_count", UNSET)

        _detection_strategies = d.pop("detection_strategies", UNSET)
        detection_strategies: list[DetectionStrategy] | Unset = UNSET
        if _detection_strategies is not UNSET:
            detection_strategies = []
            for detection_strategies_item_data in _detection_strategies:
                detection_strategies_item = DetectionStrategy.from_dict(detection_strategies_item_data)

                detection_strategies.append(detection_strategies_item)

        _log_sources = d.pop("log_sources", UNSET)
        log_sources: list[LogSourceGroup] | Unset = UNSET
        if _log_sources is not UNSET:
            log_sources = []
            for log_sources_item_data in _log_sources:
                log_sources_item = LogSourceGroup.from_dict(log_sources_item_data)

                log_sources.append(log_sources_item)

        mitigation_ids = cast(list[str], d.pop("mitigation_ids", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        platforms = cast(list[str], d.pop("platforms", UNSET))

        tactics = cast(list[str], d.pop("tactics", UNSET))

        inventory_technique_profile = cls(
            technique_id=technique_id,
            cve_count=cve_count,
            detection_strategies=detection_strategies,
            log_sources=log_sources,
            mitigation_ids=mitigation_ids,
            name=name,
            platforms=platforms,
            tactics=tactics,
        )

        inventory_technique_profile.additional_properties = d
        return inventory_technique_profile

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
