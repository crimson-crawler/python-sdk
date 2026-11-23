from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Literal, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.batch_group_item_framework import BatchGroupItemFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchGroupItem")


@_attrs_define
class BatchGroupItem:
    """Batch item: enrich a threat actor group.

    Attributes:
        framework (BatchGroupItemFramework | Unset): ATT&CK framework: enterprise, ics, or mobile Default:
            BatchGroupItemFramework.ENTERPRISE.
        group_id (None | str | Unset): ATT&CK group ID for direct lookup (e.g. G0016)
        include (list[str] | Unset): Response layers to include. Replaces the default list. Allowed values: campaigns,
            cves, defend, details, detections, knowledgebase, log_sources, misp, mitigations, navigator, nist_controls,
            software, summary, techniques, tie, versions. `defend_full` and `log_sources_full` restore full rows. Technique
            pages are ordered by ID. `log_source_refs` maps each technique ID to indices in the page's `log_source_catalog`.
        limit (int | Unset): Maximum group techniques per page (1–50) Default: 10.
        offset (int | Unset): Zero-based offset into the sorted technique IDs Default: 0.
        search (None | str | Unset): Text query to search groups by name or alias (e.g. 'APT28')
        snapshot_id (None | str | Unset): Snapshot returned by page 0; required for later pages
        type_ (Literal['group'] | Unset): Selects threat-group enrichment for this batch item Default: 'group'.
    """

    framework: BatchGroupItemFramework | Unset = BatchGroupItemFramework.ENTERPRISE
    group_id: None | str | Unset = UNSET
    include: list[str] | Unset = UNSET
    limit: int | Unset = 10
    offset: int | Unset = 0
    search: None | str | Unset = UNSET
    snapshot_id: None | str | Unset = UNSET
    type_: Literal["group"] | Unset = "group"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework: str | Unset = UNSET
        if not isinstance(self.framework, Unset):
            framework = self.framework.value

        group_id: None | str | Unset
        if isinstance(self.group_id, Unset):
            group_id = UNSET
        else:
            group_id = self.group_id

        include: list[str] | Unset = UNSET
        if not isinstance(self.include, Unset):
            include = self.include

        limit = self.limit

        offset = self.offset

        search: None | str | Unset
        if isinstance(self.search, Unset):
            search = UNSET
        else:
            search = self.search

        snapshot_id: None | str | Unset
        if isinstance(self.snapshot_id, Unset):
            snapshot_id = UNSET
        else:
            snapshot_id = self.snapshot_id

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if framework is not UNSET:
            field_dict["framework"] = framework
        if group_id is not UNSET:
            field_dict["group_id"] = group_id
        if include is not UNSET:
            field_dict["include"] = include
        if limit is not UNSET:
            field_dict["limit"] = limit
        if offset is not UNSET:
            field_dict["offset"] = offset
        if search is not UNSET:
            field_dict["search"] = search
        if snapshot_id is not UNSET:
            field_dict["snapshot_id"] = snapshot_id
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _framework = d.pop("framework", UNSET)
        framework: BatchGroupItemFramework | Unset
        if isinstance(_framework, Unset):
            framework = UNSET
        else:
            framework = BatchGroupItemFramework(_framework)

        def _parse_group_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        group_id = _parse_group_id(d.pop("group_id", UNSET))

        include = cast(list[str], d.pop("include", UNSET))

        limit = d.pop("limit", UNSET)

        offset = d.pop("offset", UNSET)

        def _parse_search(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        search = _parse_search(d.pop("search", UNSET))

        def _parse_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        snapshot_id = _parse_snapshot_id(d.pop("snapshot_id", UNSET))

        type_ = cast(Literal["group"] | Unset, d.pop("type", UNSET))
        if type_ != "group" and not isinstance(type_, Unset):
            raise ValueError(f"type must match const 'group', got '{type_}'")

        batch_group_item = cls(
            framework=framework,
            group_id=group_id,
            include=include,
            limit=limit,
            offset=offset,
            search=search,
            snapshot_id=snapshot_id,
            type_=type_,
        )

        batch_group_item.additional_properties = d
        return batch_group_item

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
