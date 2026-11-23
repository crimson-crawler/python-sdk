from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.analytic_detail_log_source_references_item import AnalyticDetailLogSourceReferencesItem
    from ..models.analytic_detail_mutable_elements_item import AnalyticDetailMutableElementsItem


T = TypeVar("T", bound="AnalyticDetail")


@_attrs_define
class AnalyticDetail:
    """One ATT&CK v18 analytic with the fields that make it implementable.

    Attributes:
        description (str | Unset): The analytic's detection prose Default: ''.
        log_source_references (list[AnalyticDetailLogSourceReferencesItem] | Unset): Per-analytic log source/channel
            mapping ({name, channel, x_mitre_data_component_ref}) — the concrete collection point to configure. 2,255 of
            2,311 enterprise analytics carry it.
        mutable_elements (list[AnalyticDetailMutableElementsItem] | Unset): Tunable fields for this analytic ({field,
            description} — e.g. TargetDLLDirectory, SignedImageValidation). 2,174 of 2,311 enterprise analytics carry them.
        name (str | Unset): Analytic name (e.g. 'Monitor DLL Search Order Hijacking') Default: ''.
    """

    description: str | Unset = ""
    log_source_references: list[AnalyticDetailLogSourceReferencesItem] | Unset = UNSET
    mutable_elements: list[AnalyticDetailMutableElementsItem] | Unset = UNSET
    name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.analytic_detail_log_source_references_item import (
            AnalyticDetailLogSourceReferencesItem,  # noqa: PLC0415
        )
        from ..models.analytic_detail_mutable_elements_item import AnalyticDetailMutableElementsItem  # noqa: PLC0415

        description = self.description

        log_source_references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.log_source_references, Unset):
            log_source_references = []
            for log_source_references_item_data in self.log_source_references:
                log_source_references_item = log_source_references_item_data.to_dict()
                log_source_references.append(log_source_references_item)

        mutable_elements: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mutable_elements, Unset):
            mutable_elements = []
            for mutable_elements_item_data in self.mutable_elements:
                mutable_elements_item = mutable_elements_item_data.to_dict()
                mutable_elements.append(mutable_elements_item)

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if log_source_references is not UNSET:
            field_dict["log_source_references"] = log_source_references
        if mutable_elements is not UNSET:
            field_dict["mutable_elements"] = mutable_elements
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.analytic_detail_log_source_references_item import (
            AnalyticDetailLogSourceReferencesItem,  # noqa: PLC0415
        )
        from ..models.analytic_detail_mutable_elements_item import AnalyticDetailMutableElementsItem  # noqa: PLC0415

        d = dict(src_dict)
        description = d.pop("description", UNSET)

        _log_source_references = d.pop("log_source_references", UNSET)
        log_source_references: list[AnalyticDetailLogSourceReferencesItem] | Unset = UNSET
        if _log_source_references is not UNSET:
            log_source_references = []
            for log_source_references_item_data in _log_source_references:
                log_source_references_item = AnalyticDetailLogSourceReferencesItem.from_dict(
                    log_source_references_item_data
                )

                log_source_references.append(log_source_references_item)

        _mutable_elements = d.pop("mutable_elements", UNSET)
        mutable_elements: list[AnalyticDetailMutableElementsItem] | Unset = UNSET
        if _mutable_elements is not UNSET:
            mutable_elements = []
            for mutable_elements_item_data in _mutable_elements:
                mutable_elements_item = AnalyticDetailMutableElementsItem.from_dict(mutable_elements_item_data)

                mutable_elements.append(mutable_elements_item)

        name = d.pop("name", UNSET)

        analytic_detail = cls(
            description=description,
            log_source_references=log_source_references,
            mutable_elements=mutable_elements,
            name=name,
        )

        analytic_detail.additional_properties = d
        return analytic_detail

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
