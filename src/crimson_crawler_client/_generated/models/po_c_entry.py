from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PoCEntry")


@_attrs_define
class PoCEntry:
    """Proof-of-concept exploit from GitHub.

    Attributes:
        created_at (str | Unset): Repository creation date (ISO 8601) Default: ''.
        description (None | str | Unset): Repository description
        forks_count (int | Unset): GitHub forks Default: 0.
        owner (str | Unset): Repository owner login Default: ''.
        repo_name (str | Unset): Repository full name (owner/repo) Default: ''.
        repo_url (str | Unset): GitHub repository URL Default: ''.
        stargazers_count (int | Unset): GitHub stars Default: 0.
        topics (list[str] | Unset): Repository topics/tags
        updated_at (str | Unset): Last update date (ISO 8601) Default: ''.
    """

    created_at: str | Unset = ""
    description: None | str | Unset = UNSET
    forks_count: int | Unset = 0
    owner: str | Unset = ""
    repo_name: str | Unset = ""
    repo_url: str | Unset = ""
    stargazers_count: int | Unset = 0
    topics: list[str] | Unset = UNSET
    updated_at: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        forks_count = self.forks_count

        owner = self.owner

        repo_name = self.repo_name

        repo_url = self.repo_url

        stargazers_count = self.stargazers_count

        topics: list[str] | Unset = UNSET
        if not isinstance(self.topics, Unset):
            topics = self.topics

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if description is not UNSET:
            field_dict["description"] = description
        if forks_count is not UNSET:
            field_dict["forks_count"] = forks_count
        if owner is not UNSET:
            field_dict["owner"] = owner
        if repo_name is not UNSET:
            field_dict["repo_name"] = repo_name
        if repo_url is not UNSET:
            field_dict["repo_url"] = repo_url
        if stargazers_count is not UNSET:
            field_dict["stargazers_count"] = stargazers_count
        if topics is not UNSET:
            field_dict["topics"] = topics
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        forks_count = d.pop("forks_count", UNSET)

        owner = d.pop("owner", UNSET)

        repo_name = d.pop("repo_name", UNSET)

        repo_url = d.pop("repo_url", UNSET)

        stargazers_count = d.pop("stargazers_count", UNSET)

        topics = cast(list[str], d.pop("topics", UNSET))

        updated_at = d.pop("updated_at", UNSET)

        po_c_entry = cls(
            created_at=created_at,
            description=description,
            forks_count=forks_count,
            owner=owner,
            repo_name=repo_name,
            repo_url=repo_url,
            stargazers_count=stargazers_count,
            topics=topics,
            updated_at=updated_at,
        )

        po_c_entry.additional_properties = d
        return po_c_entry

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
