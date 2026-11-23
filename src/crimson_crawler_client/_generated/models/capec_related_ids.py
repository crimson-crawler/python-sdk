from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CAPECRelatedIds")


@_attrs_define
class CAPECRelatedIds:
    """A CAPEC pattern's own pattern-to-pattern graph, resolved to CAPEC ids.

    The five axes the catalogue carries as STIX ids (`x_capec_*_refs`) — unusable for joining back
    to a CAPEC id — resolved against the bundle's own objects. An edge whose target the bundle does
    not hold, or that is not itself a CAPEC pattern, is omitted rather than guessed at.

        Attributes:
            can_follow (list[str] | Unset): CAPEC ids this one can follow in a chain
            can_precede (list[str] | Unset): CAPEC ids that can follow this one in a chain
            child_of (list[str] | Unset): CAPEC ids of the parent pattern(s) this one specialises
            parent_of (list[str] | Unset): CAPEC ids this pattern is a parent of
            peer_of (list[str] | Unset): CAPEC ids this pattern is a peer of
    """

    can_follow: list[str] | Unset = UNSET
    can_precede: list[str] | Unset = UNSET
    child_of: list[str] | Unset = UNSET
    parent_of: list[str] | Unset = UNSET
    peer_of: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        can_follow: list[str] | Unset = UNSET
        if not isinstance(self.can_follow, Unset):
            can_follow = self.can_follow

        can_precede: list[str] | Unset = UNSET
        if not isinstance(self.can_precede, Unset):
            can_precede = self.can_precede

        child_of: list[str] | Unset = UNSET
        if not isinstance(self.child_of, Unset):
            child_of = self.child_of

        parent_of: list[str] | Unset = UNSET
        if not isinstance(self.parent_of, Unset):
            parent_of = self.parent_of

        peer_of: list[str] | Unset = UNSET
        if not isinstance(self.peer_of, Unset):
            peer_of = self.peer_of

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if can_follow is not UNSET:
            field_dict["can_follow"] = can_follow
        if can_precede is not UNSET:
            field_dict["can_precede"] = can_precede
        if child_of is not UNSET:
            field_dict["child_of"] = child_of
        if parent_of is not UNSET:
            field_dict["parent_of"] = parent_of
        if peer_of is not UNSET:
            field_dict["peer_of"] = peer_of

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        can_follow = cast(list[str], d.pop("can_follow", UNSET))

        can_precede = cast(list[str], d.pop("can_precede", UNSET))

        child_of = cast(list[str], d.pop("child_of", UNSET))

        parent_of = cast(list[str], d.pop("parent_of", UNSET))

        peer_of = cast(list[str], d.pop("peer_of", UNSET))

        capec_related_ids = cls(
            can_follow=can_follow,
            can_precede=can_precede,
            child_of=child_of,
            parent_of=parent_of,
            peer_of=peer_of,
        )

        capec_related_ids.additional_properties = d
        return capec_related_ids

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
