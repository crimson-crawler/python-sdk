from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.et_scada_rule_match import ETScadaRuleMatch
from ..types import UNSET, Unset

T = TypeVar("T", bound="ETScadaRule")


@_attrs_define
class ETScadaRule:
    """One ET SCADA rule's metadata, not its executable rule body.

    Attributes:
        enabled (bool): Whether the upstream rule is enabled
        licence (str): Ruleset licence
        match (ETScadaRuleMatch): Whether the rule matched a CVE or an OT protocol
        msg (str): Rule message
        rev (int): Signature revision
        sid (int): Suricata signature identifier
        source (str): Source ruleset name
        source_url (str): Source ruleset URL
        classtype (None | str | Unset): Suricata classification
    """

    enabled: bool
    licence: str
    match: ETScadaRuleMatch
    msg: str
    rev: int
    sid: int
    source: str
    source_url: str
    classtype: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enabled = self.enabled

        licence = self.licence

        match = self.match.value

        msg = self.msg

        rev = self.rev

        sid = self.sid

        source = self.source

        source_url = self.source_url

        classtype: None | str | Unset
        if isinstance(self.classtype, Unset):
            classtype = UNSET
        else:
            classtype = self.classtype

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "enabled": enabled,
                "licence": licence,
                "match": match,
                "msg": msg,
                "rev": rev,
                "sid": sid,
                "source": source,
                "source_url": source_url,
            }
        )
        if classtype is not UNSET:
            field_dict["classtype"] = classtype

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        enabled = d.pop("enabled")

        licence = d.pop("licence")

        match = ETScadaRuleMatch(d.pop("match"))

        msg = d.pop("msg")

        rev = d.pop("rev")

        sid = d.pop("sid")

        source = d.pop("source")

        source_url = d.pop("source_url")

        def _parse_classtype(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        classtype = _parse_classtype(d.pop("classtype", UNSET))

        et_scada_rule = cls(
            enabled=enabled,
            licence=licence,
            match=match,
            msg=msg,
            rev=rev,
            sid=sid,
            source=source,
            source_url=source_url,
            classtype=classtype,
        )

        et_scada_rule.additional_properties = d
        return et_scada_rule

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
