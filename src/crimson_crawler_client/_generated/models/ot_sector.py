from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OTSector")


@_attrs_define
class OTSector:
    """One critical-infrastructure sector derived for a CVE or product.

    ``source`` names the derivation: ``ics-advisory-project`` (the structured CSV,
    preferred), ``csaf`` (the advisory's own notes), or ``vendor-map`` (the
    curated vendor→sector table). The ICS Advisory Project rows carry its ODbL
    attribution and are never presented as CISA's own sector metadata.

        Attributes:
            sector (str): Canonical slug from the curated sector vocabulary (every live ICS Advisory Project label maps; see
                `sector_aliases`)
            source (str): Which derivation produced this row
            advisory_ids (list[str] | Unset): Advisories that name this sector
            attribution (None | str | Unset): Required attribution, when the source carries one
            label (None | str | Unset): The upstream display label
            source_url (str | Unset): The source's URL Default: ''.
    """

    sector: str
    source: str
    advisory_ids: list[str] | Unset = UNSET
    attribution: None | str | Unset = UNSET
    label: None | str | Unset = UNSET
    source_url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sector = self.sector

        source = self.source

        advisory_ids: list[str] | Unset = UNSET
        if not isinstance(self.advisory_ids, Unset):
            advisory_ids = self.advisory_ids

        attribution: None | str | Unset
        if isinstance(self.attribution, Unset):
            attribution = UNSET
        else:
            attribution = self.attribution

        label: None | str | Unset
        if isinstance(self.label, Unset):
            label = UNSET
        else:
            label = self.label

        source_url = self.source_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sector": sector,
                "source": source,
            }
        )
        if advisory_ids is not UNSET:
            field_dict["advisory_ids"] = advisory_ids
        if attribution is not UNSET:
            field_dict["attribution"] = attribution
        if label is not UNSET:
            field_dict["label"] = label
        if source_url is not UNSET:
            field_dict["source_url"] = source_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        sector = d.pop("sector")

        source = d.pop("source")

        advisory_ids = cast(list[str], d.pop("advisory_ids", UNSET))

        def _parse_attribution(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attribution = _parse_attribution(d.pop("attribution", UNSET))

        def _parse_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        label = _parse_label(d.pop("label", UNSET))

        source_url = d.pop("source_url", UNSET)

        ot_sector = cls(
            sector=sector,
            source=source,
            advisory_ids=advisory_ids,
            attribution=attribution,
            label=label,
            source_url=source_url,
        )

        ot_sector.additional_properties = d
        return ot_sector

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
