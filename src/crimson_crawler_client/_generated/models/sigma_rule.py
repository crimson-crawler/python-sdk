from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SigmaRule")


@_attrs_define
class SigmaRule:
    """One SigmaHQ detection rule, indexed by the CVE ids and ATT&CK techniques it tags.

    Sigma rules are licensed under the Detection Rule License 1.1 (DRL-1.1); the index
    carries attribution and never redistributes the rule body (`path` names the rule file
    in the seeded clone).

        Attributes:
            path (str): Rule file path inside the seeded Sigma corpus
            rule_id (str): Sigma rule id
            source_url (str): SigmaHQ repository URL
            title (str): Rule title
            cve_ids (list[str] | Unset): CVE ids normalised from the tags
            date (None | str | Unset): Rule creation date
            description (None | str | Unset): Rule description
            level (None | str | Unset): Rule severity level
            modified (None | str | Unset): Rule modification date
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            source (str | Unset): Stable source label; rules are DRL-1.1 Default: 'sigma'.
            status (None | str | Unset): Rule status (test, stable, …)
            tags (list[str] | Unset): The rule's own tags
            technique_ids (list[str] | Unset): ATT&CK technique ids normalised from the tags
    """

    path: str
    rule_id: str
    source_url: str
    title: str
    cve_ids: list[str] | Unset = UNSET
    date: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    level: None | str | Unset = UNSET
    modified: None | str | Unset = UNSET
    retrieved_at: str | Unset = ""
    source: str | Unset = "sigma"
    status: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    technique_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        path = self.path

        rule_id = self.rule_id

        source_url = self.source_url

        title = self.title

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        date: None | str | Unset
        if isinstance(self.date, Unset):
            date = UNSET
        else:
            date = self.date

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        level: None | str | Unset
        if isinstance(self.level, Unset):
            level = UNSET
        else:
            level = self.level

        modified: None | str | Unset
        if isinstance(self.modified, Unset):
            modified = UNSET
        else:
            modified = self.modified

        retrieved_at = self.retrieved_at

        source = self.source

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "path": path,
                "rule_id": rule_id,
                "source_url": source_url,
                "title": title,
            }
        )
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if date is not UNSET:
            field_dict["date"] = date
        if description is not UNSET:
            field_dict["description"] = description
        if level is not UNSET:
            field_dict["level"] = level
        if modified is not UNSET:
            field_dict["modified"] = modified
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if source is not UNSET:
            field_dict["source"] = source
        if status is not UNSET:
            field_dict["status"] = status
        if tags is not UNSET:
            field_dict["tags"] = tags
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        path = d.pop("path")

        rule_id = d.pop("rule_id")

        source_url = d.pop("source_url")

        title = d.pop("title")

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        def _parse_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date = _parse_date(d.pop("date", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_level(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        level = _parse_level(d.pop("level", UNSET))

        def _parse_modified(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified = _parse_modified(d.pop("modified", UNSET))

        retrieved_at = d.pop("retrieved_at", UNSET)

        source = d.pop("source", UNSET)

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        tags = cast(list[str], d.pop("tags", UNSET))

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        sigma_rule = cls(
            path=path,
            rule_id=rule_id,
            source_url=source_url,
            title=title,
            cve_ids=cve_ids,
            date=date,
            description=description,
            level=level,
            modified=modified,
            retrieved_at=retrieved_at,
            source=source,
            status=status,
            tags=tags,
            technique_ids=technique_ids,
        )

        sigma_rule.additional_properties = d
        return sigma_rule

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
