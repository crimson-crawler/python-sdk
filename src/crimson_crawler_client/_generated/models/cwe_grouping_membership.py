from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cwe_grouping_member import CWEGroupingMember


T = TypeVar("T", bound="CWEGroupingMembership")


@_attrs_define
class CWEGroupingMembership:
    """What a CWE Category/View CONTAINS — the reverse direction of ``CWEDetail.categories``/``views``.

    ``/v1/enrich/cwe`` answers a Category/View id with this block instead of a weakness profile:
    the id is real and resolvable, it simply groups weaknesses rather than being one. Members come
    from the catalogue's own membership list, in the order it declares, and nothing is
    substituted — a member weakness is never served as the requested object.

        Attributes:
            grouping_id (str | Unset): The Category or View this membership belongs to Default: ''.
            kind (str | Unset): Category or View — MITRE's own grouping kind Default: ''.
            member_count (int | Unset): How many members the catalogue lists for this grouping Default: 0.
            members (list[CWEGroupingMember] | Unset): The members, in the catalogue's own order (never re-sorted, never
                truncated)
            members_complete (bool | Unset): False when the membership read did not resolve — `members` is then empty
                because the read failed, not because the grouping is empty. `errors[]` carries the failure. Default: True.
            name (str | Unset): Grouping title Default: ''.
    """

    grouping_id: str | Unset = ""
    kind: str | Unset = ""
    member_count: int | Unset = 0
    members: list[CWEGroupingMember] | Unset = UNSET
    members_complete: bool | Unset = True
    name: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cwe_grouping_member import CWEGroupingMember  # noqa: PLC0415

        grouping_id = self.grouping_id

        kind = self.kind

        member_count = self.member_count

        members: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.members, Unset):
            members = []
            for members_item_data in self.members:
                members_item = members_item_data.to_dict()
                members.append(members_item)

        members_complete = self.members_complete

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if grouping_id is not UNSET:
            field_dict["grouping_id"] = grouping_id
        if kind is not UNSET:
            field_dict["kind"] = kind
        if member_count is not UNSET:
            field_dict["member_count"] = member_count
        if members is not UNSET:
            field_dict["members"] = members
        if members_complete is not UNSET:
            field_dict["members_complete"] = members_complete
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cwe_grouping_member import CWEGroupingMember  # noqa: PLC0415

        d = dict(src_dict)
        grouping_id = d.pop("grouping_id", UNSET)

        kind = d.pop("kind", UNSET)

        member_count = d.pop("member_count", UNSET)

        _members = d.pop("members", UNSET)
        members: list[CWEGroupingMember] | Unset = UNSET
        if _members is not UNSET:
            members = []
            for members_item_data in _members:
                members_item = CWEGroupingMember.from_dict(members_item_data)

                members.append(members_item)

        members_complete = d.pop("members_complete", UNSET)

        name = d.pop("name", UNSET)

        cwe_grouping_membership = cls(
            grouping_id=grouping_id,
            kind=kind,
            member_count=member_count,
            members=members,
            members_complete=members_complete,
            name=name,
        )

        cwe_grouping_membership.additional_properties = d
        return cwe_grouping_membership

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
