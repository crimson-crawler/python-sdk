from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CellularAnnotation")


@_attrs_define
class CellularAnnotation:
    """One row of the 5G CVE-annotated dataset (Zenodo 17450053, CC-BY-4.0).

    `native_5g` / `lte` / `auxiliary` are the row's own `Multiclass` tag, so the
    booleans and `tags` can never disagree.

        Attributes:
            auxiliary (bool): The row is tagged auxiliary
            cve_id (str): CVE the row annotates
            doi (str): Dataset DOI
            lte (bool): The row is tagged LTE
            native_5g (bool): The row is tagged 5G-native
            source_url (str): The Zenodo file URL
            dataset_version (None | str | Unset): Dataset version identifier
            source (str | Unset): Stable source label Default: '5g_cve_dataset'.
            tags (list[str] | Unset): The dataset's own classification tags
    """

    auxiliary: bool
    cve_id: str
    doi: str
    lte: bool
    native_5g: bool
    source_url: str
    dataset_version: None | str | Unset = UNSET
    source: str | Unset = "5g_cve_dataset"
    tags: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        auxiliary = self.auxiliary

        cve_id = self.cve_id

        doi = self.doi

        lte = self.lte

        native_5g = self.native_5g

        source_url = self.source_url

        dataset_version: None | str | Unset
        if isinstance(self.dataset_version, Unset):
            dataset_version = UNSET
        else:
            dataset_version = self.dataset_version

        source = self.source

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "auxiliary": auxiliary,
                "cve_id": cve_id,
                "doi": doi,
                "lte": lte,
                "native_5g": native_5g,
                "source_url": source_url,
            }
        )
        if dataset_version is not UNSET:
            field_dict["dataset_version"] = dataset_version
        if source is not UNSET:
            field_dict["source"] = source
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        auxiliary = d.pop("auxiliary")

        cve_id = d.pop("cve_id")

        doi = d.pop("doi")

        lte = d.pop("lte")

        native_5g = d.pop("native_5g")

        source_url = d.pop("source_url")

        def _parse_dataset_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dataset_version = _parse_dataset_version(d.pop("dataset_version", UNSET))

        source = d.pop("source", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        cellular_annotation = cls(
            auxiliary=auxiliary,
            cve_id=cve_id,
            doi=doi,
            lte=lte,
            native_5g=native_5g,
            source_url=source_url,
            dataset_version=dataset_version,
            source=source,
            tags=tags,
        )

        cellular_annotation.additional_properties = d
        return cellular_annotation

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
