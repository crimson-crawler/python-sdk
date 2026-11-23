from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AffectedProduct")


@_attrs_define
class AffectedProduct:
    """Software product confirmed vulnerable by CPE match.

    Attributes:
        cpe (str | Unset): CPE 2.3 URI identifying the product Default: ''.
        edition (None | str | Unset): CPE 2.3 `edition` qualifier. `null` when unset; '*' means wildcard
        match_criteria_id (None | str | Unset): NVD `matchCriteriaId` of the configuration criterion this row belongs to
            (join key into NVD's CPE match data)
        match_string (None | str | Unset): The criterion's wildcard CPE matchstring — the range this row is an
            enumerated instance of
        part (str | Unset): CPE part: 'a' application, 'o' operating system, 'h' hardware Default: ''.
        product (str | Unset): Product name Default: ''.
        revoked (bool | Unset): Whether this CPE entry has been revoked from the dictionary Default: False.
        sw_edition (None | str | Unset): CPE 2.3 `sw_edition` qualifier (e.g. `enterprise`, `professional`). `null` when
            unset
        target_hw (None | str | Unset): CPE 2.3 `target_hw` qualifier — the hardware platform
        target_sw (None | str | Unset): CPE 2.3 `target_sw` qualifier — the software environment the product runs on
            (e.g. `windows`)
        update (None | str | Unset): CPE 2.3 `update` qualifier (e.g. `sp1`, `rc2`). `null` when the struct omits it;
            '*' means wildcard
        vendor (str | Unset): Vendor name Default: ''.
        version (str | Unset): Affected version (empty if all versions) Default: ''.
        version_end_excluding (None | str | Unset): Range bound: versions before this value are covered
        version_end_including (None | str | Unset): Range bound: versions up to and including this value are covered
        version_start_excluding (None | str | Unset): Range bound: versions after this value are covered by the
            criterion
        version_start_including (None | str | Unset): Range bound: versions from this value up are covered by the
            criterion
        vulnerable (bool | None | Unset): NVD's own verdict for this configuration entry: `true` when the CPE appears
            under `x_cpes.vulnerable`, `false` when NVD lists it under `x_cpes.not_vulnerable` (the product is in the CVE's
            configuration but explicitly NOT affected — e.g. the hardware platform a vulnerable firmware runs on), `null`
            when no match criterion references the row. Rows without this flag cannot be told apart from genuinely affected
            ones.
    """

    cpe: str | Unset = ""
    edition: None | str | Unset = UNSET
    match_criteria_id: None | str | Unset = UNSET
    match_string: None | str | Unset = UNSET
    part: str | Unset = ""
    product: str | Unset = ""
    revoked: bool | Unset = False
    sw_edition: None | str | Unset = UNSET
    target_hw: None | str | Unset = UNSET
    target_sw: None | str | Unset = UNSET
    update: None | str | Unset = UNSET
    vendor: str | Unset = ""
    version: str | Unset = ""
    version_end_excluding: None | str | Unset = UNSET
    version_end_including: None | str | Unset = UNSET
    version_start_excluding: None | str | Unset = UNSET
    version_start_including: None | str | Unset = UNSET
    vulnerable: bool | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cpe = self.cpe

        edition: None | str | Unset
        if isinstance(self.edition, Unset):
            edition = UNSET
        else:
            edition = self.edition

        match_criteria_id: None | str | Unset
        if isinstance(self.match_criteria_id, Unset):
            match_criteria_id = UNSET
        else:
            match_criteria_id = self.match_criteria_id

        match_string: None | str | Unset
        if isinstance(self.match_string, Unset):
            match_string = UNSET
        else:
            match_string = self.match_string

        part = self.part

        product = self.product

        revoked = self.revoked

        sw_edition: None | str | Unset
        if isinstance(self.sw_edition, Unset):
            sw_edition = UNSET
        else:
            sw_edition = self.sw_edition

        target_hw: None | str | Unset
        if isinstance(self.target_hw, Unset):
            target_hw = UNSET
        else:
            target_hw = self.target_hw

        target_sw: None | str | Unset
        if isinstance(self.target_sw, Unset):
            target_sw = UNSET
        else:
            target_sw = self.target_sw

        update: None | str | Unset
        if isinstance(self.update, Unset):
            update = UNSET
        else:
            update = self.update

        vendor = self.vendor

        version = self.version

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

        vulnerable: bool | None | Unset
        if isinstance(self.vulnerable, Unset):
            vulnerable = UNSET
        else:
            vulnerable = self.vulnerable

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if edition is not UNSET:
            field_dict["edition"] = edition
        if match_criteria_id is not UNSET:
            field_dict["match_criteria_id"] = match_criteria_id
        if match_string is not UNSET:
            field_dict["match_string"] = match_string
        if part is not UNSET:
            field_dict["part"] = part
        if product is not UNSET:
            field_dict["product"] = product
        if revoked is not UNSET:
            field_dict["revoked"] = revoked
        if sw_edition is not UNSET:
            field_dict["sw_edition"] = sw_edition
        if target_hw is not UNSET:
            field_dict["target_hw"] = target_hw
        if target_sw is not UNSET:
            field_dict["target_sw"] = target_sw
        if update is not UNSET:
            field_dict["update"] = update
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version
        if version_end_excluding is not UNSET:
            field_dict["version_end_excluding"] = version_end_excluding
        if version_end_including is not UNSET:
            field_dict["version_end_including"] = version_end_including
        if version_start_excluding is not UNSET:
            field_dict["version_start_excluding"] = version_start_excluding
        if version_start_including is not UNSET:
            field_dict["version_start_including"] = version_start_including
        if vulnerable is not UNSET:
            field_dict["vulnerable"] = vulnerable

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cpe = d.pop("cpe", UNSET)

        def _parse_edition(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        edition = _parse_edition(d.pop("edition", UNSET))

        def _parse_match_criteria_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        match_criteria_id = _parse_match_criteria_id(d.pop("match_criteria_id", UNSET))

        def _parse_match_string(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        match_string = _parse_match_string(d.pop("match_string", UNSET))

        part = d.pop("part", UNSET)

        product = d.pop("product", UNSET)

        revoked = d.pop("revoked", UNSET)

        def _parse_sw_edition(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sw_edition = _parse_sw_edition(d.pop("sw_edition", UNSET))

        def _parse_target_hw(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_hw = _parse_target_hw(d.pop("target_hw", UNSET))

        def _parse_target_sw(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_sw = _parse_target_sw(d.pop("target_sw", UNSET))

        def _parse_update(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        update = _parse_update(d.pop("update", UNSET))

        vendor = d.pop("vendor", UNSET)

        version = d.pop("version", UNSET)

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

        def _parse_vulnerable(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        vulnerable = _parse_vulnerable(d.pop("vulnerable", UNSET))

        affected_product = cls(
            cpe=cpe,
            edition=edition,
            match_criteria_id=match_criteria_id,
            match_string=match_string,
            part=part,
            product=product,
            revoked=revoked,
            sw_edition=sw_edition,
            target_hw=target_hw,
            target_sw=target_sw,
            update=update,
            vendor=vendor,
            version=version,
            version_end_excluding=version_end_excluding,
            version_end_including=version_end_including,
            version_start_excluding=version_start_excluding,
            version_start_including=version_start_including,
            vulnerable=vulnerable,
        )

        affected_product.additional_properties = d
        return affected_product

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
