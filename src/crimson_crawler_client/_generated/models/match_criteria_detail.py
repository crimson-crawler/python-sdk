from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.affected_product import AffectedProduct


T = TypeVar("T", bound="MatchCriteriaDetail")


@_attrs_define
class MatchCriteriaDetail:
    """One NVD CPE match criterion, resolved from the `match_criteria_id` its rows publish.

    `AffectedProduct.match_criteria_id` is a join key into NVD's configuration data, and nothing
    resolved it in the other direction: a caller holding the id could read the row's inline
    matchstring and bounds but not the criterion's own identity, what it covers, or whether it has
    been revised since. This is that reverse resolution (`include=['criteria']`).

        Attributes:
            context (str | Unset): STIX `context` of the grouping, when it carries one Default: ''.
            covered_software (list[AffectedProduct] | Unset): The software rows this criterion covers — the membership its
                `matchstring` selects, which no other read returns. Rows only; `covered_software_count` is the full total
            covered_software_count (int | Unset): Total software rows the criterion covers. Equal to `len(covered_software)`
                unless the list was capped for response size, which is why the count is reported separately Default: 0.
            created (str | Unset): When NVD created the criterion (ISO 8601) Default: ''.
            criteria_id (str | Unset): The criterion's own name in NVD's export (the grouping's `name`) Default: ''.
            latest_revision (None | str | Unset): Newest revision timestamp, or null when the revision read failed
            match_criteria_id (str | Unset): NVD `matchCriteriaId` — the id the affected rows carry Default: ''.
            matchstring (str | Unset): The criterion's wildcard CPE matchstring Default: ''.
            modified (str | Unset): When NVD last revised the criterion (ISO 8601) Default: ''.
            revision_count (int | Unset): How many revisions NVD holds for this criterion (`/{criteria_id}/versions/`). The
                `matchCriteriaId` is stable across them, so this is how a caller tells that the criterion behind a cached row
                has moved; 0 when the revision read failed Default: 0.
            stix_id (str | Unset): STIX id of the grouping object Default: ''.
            version_end_excluding (None | str | Unset): Range bound: versions before here are covered
            version_end_including (None | str | Unset): Range bound: versions up to here are covered
            version_start_excluding (None | str | Unset): Range bound: versions after here are covered
            version_start_including (None | str | Unset): Range bound: versions from here up are covered
            vulnerable_cve_ids (list[str] | Unset): CVEs this criterion makes vulnerable, as NVD's own bundle states them
    """

    context: str | Unset = ""
    covered_software: list[AffectedProduct] | Unset = UNSET
    covered_software_count: int | Unset = 0
    created: str | Unset = ""
    criteria_id: str | Unset = ""
    latest_revision: None | str | Unset = UNSET
    match_criteria_id: str | Unset = ""
    matchstring: str | Unset = ""
    modified: str | Unset = ""
    revision_count: int | Unset = 0
    stix_id: str | Unset = ""
    version_end_excluding: None | str | Unset = UNSET
    version_end_including: None | str | Unset = UNSET
    version_start_excluding: None | str | Unset = UNSET
    version_start_including: None | str | Unset = UNSET
    vulnerable_cve_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.affected_product import AffectedProduct  # noqa: PLC0415

        context = self.context

        covered_software: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.covered_software, Unset):
            covered_software = []
            for covered_software_item_data in self.covered_software:
                covered_software_item = covered_software_item_data.to_dict()
                covered_software.append(covered_software_item)

        covered_software_count = self.covered_software_count

        created = self.created

        criteria_id = self.criteria_id

        latest_revision: None | str | Unset
        if isinstance(self.latest_revision, Unset):
            latest_revision = UNSET
        else:
            latest_revision = self.latest_revision

        match_criteria_id = self.match_criteria_id

        matchstring = self.matchstring

        modified = self.modified

        revision_count = self.revision_count

        stix_id = self.stix_id

        version_end_excluding: None | str | Unset
        if isinstance(self.version_end_excluding, Unset):
            version_end_excluding = UNSET
        else:
            version_end_excluding = self.version_end_excluding

        version_end_including: None | str | Unset
        if isinstance(self.version_end_including, Unset):
            version_end_including = UNSET
        else:
            version_end_including = self.version_end_including

        version_start_excluding: None | str | Unset
        if isinstance(self.version_start_excluding, Unset):
            version_start_excluding = UNSET
        else:
            version_start_excluding = self.version_start_excluding

        version_start_including: None | str | Unset
        if isinstance(self.version_start_including, Unset):
            version_start_including = UNSET
        else:
            version_start_including = self.version_start_including

        vulnerable_cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.vulnerable_cve_ids, Unset):
            vulnerable_cve_ids = self.vulnerable_cve_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if context is not UNSET:
            field_dict["context"] = context
        if covered_software is not UNSET:
            field_dict["covered_software"] = covered_software
        if covered_software_count is not UNSET:
            field_dict["covered_software_count"] = covered_software_count
        if created is not UNSET:
            field_dict["created"] = created
        if criteria_id is not UNSET:
            field_dict["criteria_id"] = criteria_id
        if latest_revision is not UNSET:
            field_dict["latest_revision"] = latest_revision
        if match_criteria_id is not UNSET:
            field_dict["match_criteria_id"] = match_criteria_id
        if matchstring is not UNSET:
            field_dict["matchstring"] = matchstring
        if modified is not UNSET:
            field_dict["modified"] = modified
        if revision_count is not UNSET:
            field_dict["revision_count"] = revision_count
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if version_end_excluding is not UNSET:
            field_dict["version_end_excluding"] = version_end_excluding
        if version_end_including is not UNSET:
            field_dict["version_end_including"] = version_end_including
        if version_start_excluding is not UNSET:
            field_dict["version_start_excluding"] = version_start_excluding
        if version_start_including is not UNSET:
            field_dict["version_start_including"] = version_start_including
        if vulnerable_cve_ids is not UNSET:
            field_dict["vulnerable_cve_ids"] = vulnerable_cve_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.affected_product import AffectedProduct  # noqa: PLC0415

        d = dict(src_dict)
        context = d.pop("context", UNSET)

        _covered_software = d.pop("covered_software", UNSET)
        covered_software: list[AffectedProduct] | Unset = UNSET
        if _covered_software is not UNSET:
            covered_software = []
            for covered_software_item_data in _covered_software:
                covered_software_item = AffectedProduct.from_dict(covered_software_item_data)

                covered_software.append(covered_software_item)

        covered_software_count = d.pop("covered_software_count", UNSET)

        created = d.pop("created", UNSET)

        criteria_id = d.pop("criteria_id", UNSET)

        def _parse_latest_revision(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        latest_revision = _parse_latest_revision(d.pop("latest_revision", UNSET))

        match_criteria_id = d.pop("match_criteria_id", UNSET)

        matchstring = d.pop("matchstring", UNSET)

        modified = d.pop("modified", UNSET)

        revision_count = d.pop("revision_count", UNSET)

        stix_id = d.pop("stix_id", UNSET)

        def _parse_version_end_excluding(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_end_excluding = _parse_version_end_excluding(d.pop("version_end_excluding", UNSET))

        def _parse_version_end_including(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_end_including = _parse_version_end_including(d.pop("version_end_including", UNSET))

        def _parse_version_start_excluding(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_start_excluding = _parse_version_start_excluding(d.pop("version_start_excluding", UNSET))

        def _parse_version_start_including(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_start_including = _parse_version_start_including(d.pop("version_start_including", UNSET))

        vulnerable_cve_ids = cast(list[str], d.pop("vulnerable_cve_ids", UNSET))

        match_criteria_detail = cls(
            context=context,
            covered_software=covered_software,
            covered_software_count=covered_software_count,
            created=created,
            criteria_id=criteria_id,
            latest_revision=latest_revision,
            match_criteria_id=match_criteria_id,
            matchstring=matchstring,
            modified=modified,
            revision_count=revision_count,
            stix_id=stix_id,
            version_end_excluding=version_end_excluding,
            version_end_including=version_end_including,
            version_start_excluding=version_start_excluding,
            version_start_including=version_start_including,
            vulnerable_cve_ids=vulnerable_cve_ids,
        )

        match_criteria_detail.additional_properties = d
        return match_criteria_detail

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
