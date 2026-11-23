from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ot_context import OTContext


T = TypeVar("T", bound="CVEOTContext")


@_attrs_define
class CVEOTContext:
    """One assessed CVE's OT/RF context (``assess/vulnerability-exposure``, ``include=['ot_context']``).

    Attributes:
        cve_id (str): The assessed CVE
        ot_context (OTContext): Opt-in OT/RF asset context for a CVE or product (``include=['ot_context']``).

            Every field is a deterministic derivation over data the request already reads
            or a committed/seeded table; there is no LLM and no new external source.
    """

    cve_id: str
    ot_context: OTContext
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.ot_context import OTContext  # noqa: PLC0415

        cve_id = self.cve_id

        ot_context = self.ot_context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "ot_context": ot_context,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ot_context import OTContext  # noqa: PLC0415

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        ot_context = OTContext.from_dict(d.pop("ot_context"))

        cveot_context = cls(
            cve_id=cve_id,
            ot_context=ot_context,
        )

        cveot_context.additional_properties = d
        return cveot_context

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
