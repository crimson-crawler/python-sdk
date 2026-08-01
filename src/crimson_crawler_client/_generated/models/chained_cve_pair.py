from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChainedCVEPair")


@_attrs_define
class ChainedCVEPair:
    """Two CVEs in adjacent kill-chain phases that affect the same vendor/product.

    Attributes:
        from_cve (str): CVE enabling the earlier attack phase
        to_cve (str): CVE enabling the next attack phase
        from_tactic (str | Unset): ATT&CK tactic of the source CVE Default: ''.
        shared_vendors (list[str] | Unset): Vendors/products affected by both CVEs
        to_tactic (str | Unset): ATT&CK tactic of the target CVE Default: ''.
    """

    from_cve: str
    to_cve: str
    from_tactic: str | Unset = ""
    shared_vendors: list[str] | Unset = UNSET
    to_tactic: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from_cve = self.from_cve

        to_cve = self.to_cve

        from_tactic = self.from_tactic

        shared_vendors: list[str] | Unset = UNSET
        if not isinstance(self.shared_vendors, Unset):
            shared_vendors = self.shared_vendors

        to_tactic = self.to_tactic

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "from_cve": from_cve,
                "to_cve": to_cve,
            }
        )
        if from_tactic is not UNSET:
            field_dict["from_tactic"] = from_tactic
        if shared_vendors is not UNSET:
            field_dict["shared_vendors"] = shared_vendors
        if to_tactic is not UNSET:
            field_dict["to_tactic"] = to_tactic

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        from_cve = d.pop("from_cve")

        to_cve = d.pop("to_cve")

        from_tactic = d.pop("from_tactic", UNSET)

        shared_vendors = cast(list[str], d.pop("shared_vendors", UNSET))

        to_tactic = d.pop("to_tactic", UNSET)

        chained_cve_pair = cls(
            from_cve=from_cve,
            to_cve=to_cve,
            from_tactic=from_tactic,
            shared_vendors=shared_vendors,
            to_tactic=to_tactic,
        )

        chained_cve_pair.additional_properties = d
        return chained_cve_pair

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
