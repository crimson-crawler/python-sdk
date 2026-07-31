from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.defense_triad_origin import DefenseTriadOrigin
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.d3fend_detail import D3FENDDetail
    from ..models.detection_detail import DetectionDetail
    from ..models.mitigation_detail import MitigationDetail


T = TypeVar("T", bound="DefenseTriad")


@_attrs_define
class DefenseTriad:
    """Per-technique detect + mitigate + counter guidance (deterministic pivots).

    Attributes:
        technique_id (str): ATT&CK technique ID
        d3fend (list[D3FENDDetail] | Unset): D3FEND defensive countermeasures linked to this technique
        detections (list[DetectionDetail] | Unset): ATT&CK detections (data source + component)
        mitigations (list[MitigationDetail] | Unset): ATT&CK mitigation M-codes for this technique
        origin (DefenseTriadOrigin | Unset): Where this technique entered the enrichment: ``observed`` = the source
            document explicitly cited it (a technique-type extracted reference — behavior the analyst saw); ``derived`` = it
            arrived only via enrichment (a CVE's deterministic chain-walk closure — something the vulnerabilities COULD
            enable, not necessarily what happened). Lets consumers rank observed behavior above possibility space. Default:
            DefenseTriadOrigin.DERIVED.
        technique_name (None | str | Unset): Technique name
    """

    technique_id: str
    d3fend: list[D3FENDDetail] | Unset = UNSET
    detections: list[DetectionDetail] | Unset = UNSET
    mitigations: list[MitigationDetail] | Unset = UNSET
    origin: DefenseTriadOrigin | Unset = DefenseTriadOrigin.DERIVED
    technique_name: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.mitigation_detail import MitigationDetail

        technique_id = self.technique_id

        d3fend: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.d3fend, Unset):
            d3fend = []
            for d3fend_item_data in self.d3fend:
                d3fend_item = d3fend_item_data.to_dict()
                d3fend.append(d3fend_item)

        detections: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.detections, Unset):
            detections = []
            for detections_item_data in self.detections:
                detections_item = detections_item_data.to_dict()
                detections.append(detections_item)

        mitigations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = []
            for mitigations_item_data in self.mitigations:
                mitigations_item = mitigations_item_data.to_dict()
                mitigations.append(mitigations_item)

        origin: str | Unset = UNSET
        if not isinstance(self.origin, Unset):
            origin = self.origin.value

        technique_name: None | str | Unset
        if isinstance(self.technique_name, Unset):
            technique_name = UNSET
        else:
            technique_name = self.technique_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique_id": technique_id,
            }
        )
        if d3fend is not UNSET:
            field_dict["d3fend"] = d3fend
        if detections is not UNSET:
            field_dict["detections"] = detections
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if origin is not UNSET:
            field_dict["origin"] = origin
        if technique_name is not UNSET:
            field_dict["technique_name"] = technique_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.d3fend_detail import D3FENDDetail
        from ..models.detection_detail import DetectionDetail
        from ..models.mitigation_detail import MitigationDetail

        d = dict(src_dict)
        technique_id = d.pop("technique_id")

        _d3fend = d.pop("d3fend", UNSET)
        d3fend: list[D3FENDDetail] | Unset = UNSET
        if _d3fend is not UNSET:
            d3fend = []
            for d3fend_item_data in _d3fend:
                d3fend_item = D3FENDDetail.from_dict(d3fend_item_data)

                d3fend.append(d3fend_item)

        _detections = d.pop("detections", UNSET)
        detections: list[DetectionDetail] | Unset = UNSET
        if _detections is not UNSET:
            detections = []
            for detections_item_data in _detections:
                detections_item = DetectionDetail.from_dict(detections_item_data)

                detections.append(detections_item)

        _mitigations = d.pop("mitigations", UNSET)
        mitigations: list[MitigationDetail] | Unset = UNSET
        if _mitigations is not UNSET:
            mitigations = []
            for mitigations_item_data in _mitigations:
                mitigations_item = MitigationDetail.from_dict(mitigations_item_data)

                mitigations.append(mitigations_item)

        _origin = d.pop("origin", UNSET)
        origin: DefenseTriadOrigin | Unset
        if isinstance(_origin, Unset):
            origin = UNSET
        else:
            origin = DefenseTriadOrigin(_origin)

        def _parse_technique_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        technique_name = _parse_technique_name(d.pop("technique_name", UNSET))

        defense_triad = cls(
            technique_id=technique_id,
            d3fend=d3fend,
            detections=detections,
            mitigations=mitigations,
            origin=origin,
            technique_name=technique_name,
        )

        defense_triad.additional_properties = d
        return defense_triad

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
