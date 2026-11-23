from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CellularCoreEntry")


@_attrs_define
class CellularCoreEntry:
    """One RANsacked CVE, reduced to the CVE id and the implementation it affects.

    Only the 73 CVE ids that resolve at CVE.org ship; 18 ids on the page do not exist and
    are excluded (see `ransacked_cellular_core.README.md`).

        Attributes:
            cve_id (str): CVE the RANsacked page lists
            implementation (str): The page's implementation heading (Open5GS, Magma, …) with its LTE/5G qualifier
            source_url (str): The RANsacked research page
            source (str | Unset): Stable source label Default: 'ransacked'.
    """

    cve_id: str
    implementation: str
    source_url: str
    source: str | Unset = "ransacked"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        implementation = self.implementation

        source_url = self.source_url

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "implementation": implementation,
                "source_url": source_url,
            }
        )
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        implementation = d.pop("implementation")

        source_url = d.pop("source_url")

        source = d.pop("source", UNSET)

        cellular_core_entry = cls(
            cve_id=cve_id,
            implementation=implementation,
            source_url=source_url,
            source=source,
        )

        cellular_core_entry.additional_properties = d
        return cellular_core_entry

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
