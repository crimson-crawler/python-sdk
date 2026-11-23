from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_object_reference_target import MISPObjectReferenceTarget


T = TypeVar("T", bound="MISPObjectReference")


@_attrs_define
class MISPObjectReference:
    """A named link between two attributes inside a composite MISP object.

    Attributes:
        comment (str | Unset): Analyst note on the reference Default: ''.
        referenced_id (str | Unset): Id of the referenced object or attribute in its own space Default: ''.
        referenced_type (str | Unset): What that uuid names: '0' an attribute, '1' another object (MISP's own flag) —
            the reference table is 92% object-to-object Default: ''.
        referenced_uuid (str | Unset): UUID of the referenced attribute Default: ''.
        relationship_type (str | Unset): How the referenced attribute relates to this one Default: ''.
        target (MISPObjectReferenceTarget | None | Unset): The referenced object/attribute itself, when MISP inlined it
            or a bounded lookup found it. Null alone cannot say why it is missing — read `target_state`.
        target_state (str | Unset): How far resolution got: 'resolved' (target present), 'missing' (looked up and not
            found — the ONLY state that claims the target does not exist), or 'unknown' (never looked up: the `objects`
            include was not requested, the reference is beyond the resolution cap, or the lookup failed — see `errors[]`).
            Default: 'unknown'.
    """

    comment: str | Unset = ""
    referenced_id: str | Unset = ""
    referenced_type: str | Unset = ""
    referenced_uuid: str | Unset = ""
    relationship_type: str | Unset = ""
    target: MISPObjectReferenceTarget | None | Unset = UNSET
    target_state: str | Unset = "unknown"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_object_reference_target import MISPObjectReferenceTarget  # noqa: PLC0415

        comment = self.comment

        referenced_id = self.referenced_id

        referenced_type = self.referenced_type

        referenced_uuid = self.referenced_uuid

        relationship_type = self.relationship_type

        target: dict[str, Any] | None | Unset
        if isinstance(self.target, Unset):
            target = UNSET
        elif isinstance(self.target, MISPObjectReferenceTarget):
            target = self.target.to_dict()
        else:
            target = self.target

        target_state = self.target_state

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if comment is not UNSET:
            field_dict["comment"] = comment
        if referenced_id is not UNSET:
            field_dict["referenced_id"] = referenced_id
        if referenced_type is not UNSET:
            field_dict["referenced_type"] = referenced_type
        if referenced_uuid is not UNSET:
            field_dict["referenced_uuid"] = referenced_uuid
        if relationship_type is not UNSET:
            field_dict["relationship_type"] = relationship_type
        if target is not UNSET:
            field_dict["target"] = target
        if target_state is not UNSET:
            field_dict["target_state"] = target_state

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_object_reference_target import MISPObjectReferenceTarget  # noqa: PLC0415

        d = dict(src_dict)
        comment = d.pop("comment", UNSET)

        referenced_id = d.pop("referenced_id", UNSET)

        referenced_type = d.pop("referenced_type", UNSET)

        referenced_uuid = d.pop("referenced_uuid", UNSET)

        relationship_type = d.pop("relationship_type", UNSET)

        def _parse_target(data: object) -> MISPObjectReferenceTarget | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                target_type_0 = MISPObjectReferenceTarget.from_dict(data)

                return target_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(MISPObjectReferenceTarget | None | Unset, data)

        target = _parse_target(d.pop("target", UNSET))

        target_state = d.pop("target_state", UNSET)

        misp_object_reference = cls(
            comment=comment,
            referenced_id=referenced_id,
            referenced_type=referenced_type,
            referenced_uuid=referenced_uuid,
            relationship_type=relationship_type,
            target=target,
            target_state=target_state,
        )

        misp_object_reference.additional_properties = d
        return misp_object_reference

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
