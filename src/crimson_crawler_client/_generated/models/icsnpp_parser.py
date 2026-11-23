from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ICSNPPParser")


@_attrs_define
class ICSNPPParser:
    """A locally indexed ICSNPP protocol parser and its provenance.

    Attributes:
        commit (str): Repository revision
        licence (str): Parser licence
        parser (str): Parser name
        protocol (str): Matched OT protocol taxonomy id
        repo_url (str): Parser repository URL
        source (str): Source catalog
        logs (list[str] | Unset): Zeek log names produced by the parser
    """

    commit: str
    licence: str
    parser: str
    protocol: str
    repo_url: str
    source: str
    logs: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        commit = self.commit

        licence = self.licence

        parser = self.parser

        protocol = self.protocol

        repo_url = self.repo_url

        source = self.source

        logs: list[str] | Unset = UNSET
        if not isinstance(self.logs, Unset):
            logs = self.logs

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "commit": commit,
                "licence": licence,
                "parser": parser,
                "protocol": protocol,
                "repo_url": repo_url,
                "source": source,
            }
        )
        if logs is not UNSET:
            field_dict["logs"] = logs

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        commit = d.pop("commit")

        licence = d.pop("licence")

        parser = d.pop("parser")

        protocol = d.pop("protocol")

        repo_url = d.pop("repo_url")

        source = d.pop("source")

        logs = cast(list[str], d.pop("logs", UNSET))

        icsnpp_parser = cls(
            commit=commit,
            licence=licence,
            parser=parser,
            protocol=protocol,
            repo_url=repo_url,
            source=source,
            logs=logs,
        )

        icsnpp_parser.additional_properties = d
        return icsnpp_parser

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
