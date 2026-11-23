from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.fix_availability_state import FixAvailabilityState
from ..types import UNSET, Unset

T = TypeVar("T", bound="FixAvailability")


@_attrs_define
class FixAvailability:
    """Whether a vendor fix exists for a CVE, from CSAF product status.

    ``state`` is ``vendor_fix`` when a CSAF advisory publishes a ``fixed`` or
    ``first_fixed`` product status, ``no_fix_published`` when the advisory names
    the product as ``known_affected`` but publishes no fix, and ``unknown`` when
    no CSAF advisory is in the corpus. ``eol`` is populated only on
    ``enrich/product`` when ``lifecycle`` was also requested (endoflife.date).
    ``workaround`` is currently always false: CSAF remediations are not stored
    yet, so the field is reserved rather than fabricated.

        Attributes:
            state (FixAvailabilityState): Fix availability
            advisory_ids (list[str] | Unset): CSAF tracking ids that supplied the status
            as_of (None | str | Unset): Newest advisory release date used
            eol (bool | None | Unset): Whether the product cycle is end-of-life (endoflife.date)
            fixed_versions (list[str] | Unset): Versions the advisory names as fixed
            source (str | Unset): Stable source label Default: 'csaf'.
            workaround (bool | Unset): Whether a published workaround exists (reserved) Default: False.
    """

    state: FixAvailabilityState
    advisory_ids: list[str] | Unset = UNSET
    as_of: None | str | Unset = UNSET
    eol: bool | None | Unset = UNSET
    fixed_versions: list[str] | Unset = UNSET
    source: str | Unset = "csaf"
    workaround: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        state = self.state.value

        advisory_ids: list[str] | Unset = UNSET
        if not isinstance(self.advisory_ids, Unset):
            advisory_ids = self.advisory_ids

        as_of: None | str | Unset
        if isinstance(self.as_of, Unset):
            as_of = UNSET
        else:
            as_of = self.as_of

        eol: bool | None | Unset
        if isinstance(self.eol, Unset):
            eol = UNSET
        else:
            eol = self.eol

        fixed_versions: list[str] | Unset = UNSET
        if not isinstance(self.fixed_versions, Unset):
            fixed_versions = self.fixed_versions

        source = self.source

        workaround = self.workaround

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "state": state,
            }
        )
        if advisory_ids is not UNSET:
            field_dict["advisory_ids"] = advisory_ids
        if as_of is not UNSET:
            field_dict["as_of"] = as_of
        if eol is not UNSET:
            field_dict["eol"] = eol
        if fixed_versions is not UNSET:
            field_dict["fixed_versions"] = fixed_versions
        if source is not UNSET:
            field_dict["source"] = source
        if workaround is not UNSET:
            field_dict["workaround"] = workaround

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        state = FixAvailabilityState(d.pop("state"))

        advisory_ids = cast(list[str], d.pop("advisory_ids", UNSET))

        def _parse_as_of(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        as_of = _parse_as_of(d.pop("as_of", UNSET))

        def _parse_eol(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        eol = _parse_eol(d.pop("eol", UNSET))

        fixed_versions = cast(list[str], d.pop("fixed_versions", UNSET))

        source = d.pop("source", UNSET)

        workaround = d.pop("workaround", UNSET)

        fix_availability = cls(
            state=state,
            advisory_ids=advisory_ids,
            as_of=as_of,
            eol=eol,
            fixed_versions=fixed_versions,
            source=source,
            workaround=workaround,
        )

        fix_availability.additional_properties = d
        return fix_availability

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
