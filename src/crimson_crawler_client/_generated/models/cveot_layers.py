from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.affected_chipset import AffectedChipset
    from ..models.android_bulletin import AndroidBulletin
    from ..models.cellular_annotation import CellularAnnotation
    from ..models.cellular_core_entry import CellularCoreEntry


T = TypeVar("T", bound="CVEOTLayers")


@_attrs_define
class CVEOTLayers:
    """OT and cellular corpus rows associated with one assessed CVE.

    Attributes:
        cve_id (str): The assessed CVE
        affected_chipsets (list[AffectedChipset] | Unset): Affected chipset and SoC records
        android_bulletin (AndroidBulletin | None | Unset): Associated Android security bulletin
        cellular_annotations (list[CellularAnnotation] | Unset): 5G dataset annotations
        cellular_core_entries (list[CellularCoreEntry] | Unset): RANsacked cellular-core entries
    """

    cve_id: str
    affected_chipsets: list[AffectedChipset] | Unset = UNSET
    android_bulletin: AndroidBulletin | None | Unset = UNSET
    cellular_annotations: list[CellularAnnotation] | Unset = UNSET
    cellular_core_entries: list[CellularCoreEntry] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.affected_chipset import AffectedChipset  # noqa: PLC0415
        from ..models.android_bulletin import AndroidBulletin  # noqa: PLC0415
        from ..models.cellular_annotation import CellularAnnotation  # noqa: PLC0415
        from ..models.cellular_core_entry import CellularCoreEntry  # noqa: PLC0415

        cve_id = self.cve_id

        affected_chipsets: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_chipsets, Unset):
            affected_chipsets = []
            for affected_chipsets_item_data in self.affected_chipsets:
                affected_chipsets_item = affected_chipsets_item_data.to_dict()
                affected_chipsets.append(affected_chipsets_item)

        android_bulletin: dict[str, Any] | None | Unset
        if isinstance(self.android_bulletin, Unset):
            android_bulletin = UNSET
        elif isinstance(self.android_bulletin, AndroidBulletin):
            android_bulletin = self.android_bulletin.to_dict()
        else:
            android_bulletin = self.android_bulletin

        cellular_annotations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cellular_annotations, Unset):
            cellular_annotations = []
            for cellular_annotations_item_data in self.cellular_annotations:
                cellular_annotations_item = cellular_annotations_item_data.to_dict()
                cellular_annotations.append(cellular_annotations_item)

        cellular_core_entries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cellular_core_entries, Unset):
            cellular_core_entries = []
            for cellular_core_entries_item_data in self.cellular_core_entries:
                cellular_core_entries_item = cellular_core_entries_item_data.to_dict()
                cellular_core_entries.append(cellular_core_entries_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if affected_chipsets is not UNSET:
            field_dict["affected_chipsets"] = affected_chipsets
        if android_bulletin is not UNSET:
            field_dict["android_bulletin"] = android_bulletin
        if cellular_annotations is not UNSET:
            field_dict["cellular_annotations"] = cellular_annotations
        if cellular_core_entries is not UNSET:
            field_dict["cellular_core_entries"] = cellular_core_entries

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.affected_chipset import AffectedChipset  # noqa: PLC0415
        from ..models.android_bulletin import AndroidBulletin  # noqa: PLC0415
        from ..models.cellular_annotation import CellularAnnotation  # noqa: PLC0415
        from ..models.cellular_core_entry import CellularCoreEntry  # noqa: PLC0415

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        _affected_chipsets = d.pop("affected_chipsets", UNSET)
        affected_chipsets: list[AffectedChipset] | Unset = UNSET
        if _affected_chipsets is not UNSET:
            affected_chipsets = []
            for affected_chipsets_item_data in _affected_chipsets:
                affected_chipsets_item = AffectedChipset.from_dict(affected_chipsets_item_data)

                affected_chipsets.append(affected_chipsets_item)

        def _parse_android_bulletin(data: object) -> AndroidBulletin | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                android_bulletin_type_0 = AndroidBulletin.from_dict(data)

                return android_bulletin_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AndroidBulletin | None | Unset, data)

        android_bulletin = _parse_android_bulletin(d.pop("android_bulletin", UNSET))

        _cellular_annotations = d.pop("cellular_annotations", UNSET)
        cellular_annotations: list[CellularAnnotation] | Unset = UNSET
        if _cellular_annotations is not UNSET:
            cellular_annotations = []
            for cellular_annotations_item_data in _cellular_annotations:
                cellular_annotations_item = CellularAnnotation.from_dict(cellular_annotations_item_data)

                cellular_annotations.append(cellular_annotations_item)

        _cellular_core_entries = d.pop("cellular_core_entries", UNSET)
        cellular_core_entries: list[CellularCoreEntry] | Unset = UNSET
        if _cellular_core_entries is not UNSET:
            cellular_core_entries = []
            for cellular_core_entries_item_data in _cellular_core_entries:
                cellular_core_entries_item = CellularCoreEntry.from_dict(cellular_core_entries_item_data)

                cellular_core_entries.append(cellular_core_entries_item)

        cveot_layers = cls(
            cve_id=cve_id,
            affected_chipsets=affected_chipsets,
            android_bulletin=android_bulletin,
            cellular_annotations=cellular_annotations,
            cellular_core_entries=cellular_core_entries,
        )

        cveot_layers.additional_properties = d
        return cveot_layers

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
