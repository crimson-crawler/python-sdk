from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.misp_notice_matched_on import MISPNoticeMatchedOn


T = TypeVar("T", bound="MISPNotice")


@_attrs_define
class MISPNotice:
    """An informational noticelist notice for one attribute (MISP noticelists).

    Distinct from `warninglist_hits`: a warninglist hit means "likely benign / false positive"; a notice
    means "this attribute is in a contextually notable class" (e.g. personal data under GDPR). Present
    only when an enabled noticelist actually matches — never a boolean verdict.

        Attributes:
            matched_on (MISPNoticeMatchedOn | Unset): Which attribute field matched ({field, value})
            message (None | str | Unset): The notice text MISP publishes for this entry
            noticelist (str | Unset): Noticelist name (e.g. 'gdpr') Default: ''.
            noticelist_id (str | Unset): Noticelist id Default: ''.
            ref (list[str] | Unset): Source references for the notice
            version (str | Unset): Noticelist version Default: ''.
    """

    matched_on: MISPNoticeMatchedOn | Unset = UNSET
    message: None | str | Unset = UNSET
    noticelist: str | Unset = ""
    noticelist_id: str | Unset = ""
    ref: list[str] | Unset = UNSET
    version: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.misp_notice_matched_on import MISPNoticeMatchedOn  # noqa: PLC0415

        matched_on: dict[str, Any] | Unset = UNSET
        if not isinstance(self.matched_on, Unset):
            matched_on = self.matched_on.to_dict()

        message: None | str | Unset
        if isinstance(self.message, Unset):
            message = UNSET
        else:
            message = self.message

        noticelist = self.noticelist

        noticelist_id = self.noticelist_id

        ref: list[str] | Unset = UNSET
        if not isinstance(self.ref, Unset):
            ref = self.ref

        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if matched_on is not UNSET:
            field_dict["matched_on"] = matched_on
        if message is not UNSET:
            field_dict["message"] = message
        if noticelist is not UNSET:
            field_dict["noticelist"] = noticelist
        if noticelist_id is not UNSET:
            field_dict["noticelist_id"] = noticelist_id
        if ref is not UNSET:
            field_dict["ref"] = ref
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.misp_notice_matched_on import MISPNoticeMatchedOn  # noqa: PLC0415

        d = dict(src_dict)
        _matched_on = d.pop("matched_on", UNSET)
        matched_on: MISPNoticeMatchedOn | Unset
        if isinstance(_matched_on, Unset):
            matched_on = UNSET
        else:
            matched_on = MISPNoticeMatchedOn.from_dict(_matched_on)

        def _parse_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        message = _parse_message(d.pop("message", UNSET))

        noticelist = d.pop("noticelist", UNSET)

        noticelist_id = d.pop("noticelist_id", UNSET)

        ref = cast(list[str], d.pop("ref", UNSET))

        version = d.pop("version", UNSET)

        misp_notice = cls(
            matched_on=matched_on,
            message=message,
            noticelist=noticelist,
            noticelist_id=noticelist_id,
            ref=ref,
            version=version,
        )

        misp_notice.additional_properties = d
        return misp_notice

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
