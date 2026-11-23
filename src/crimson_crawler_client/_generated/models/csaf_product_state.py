from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.csaf_product_state_status import CSAFProductStateStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="CSAFProductState")


@_attrs_define
class CSAFProductState:
    """One product-status entry of a CSAF advisory.

    `cve_id` is nullable because a CVE-less advisory is a legitimate document; such a row
    is reachable through the search route, never through `enrich/cve`.

        Attributes:
            status (CSAFProductStateStatus): CSAF product status
            cpe (None | str | Unset): CPE the entry names
            cve_id (None | str | Unset): CVE the entry applies to, or null on a CVE-less advisory
            model_numbers (list[str] | Unset): Model numbers the entry names
            product_id (None | str | Unset): CSAF product id (CSAFPID-…)
            product_name (None | str | Unset): Product name from the document
            version_range (None | str | Unset): The `vers:` expression, when the document carries one
    """

    status: CSAFProductStateStatus
    cpe: None | str | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    model_numbers: list[str] | Unset = UNSET
    product_id: None | str | Unset = UNSET
    product_name: None | str | Unset = UNSET
    version_range: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status.value

        cpe: None | str | Unset
        if isinstance(self.cpe, Unset):
            cpe = UNSET
        else:
            cpe = self.cpe

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        model_numbers: list[str] | Unset = UNSET
        if not isinstance(self.model_numbers, Unset):
            model_numbers = self.model_numbers

        product_id: None | str | Unset
        if isinstance(self.product_id, Unset):
            product_id = UNSET
        else:
            product_id = self.product_id

        product_name: None | str | Unset
        if isinstance(self.product_name, Unset):
            product_name = UNSET
        else:
            product_name = self.product_name

        version_range: None | str | Unset
        if isinstance(self.version_range, Unset):
            version_range = UNSET
        else:
            version_range = self.version_range

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
            }
        )
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if model_numbers is not UNSET:
            field_dict["model_numbers"] = model_numbers
        if product_id is not UNSET:
            field_dict["product_id"] = product_id
        if product_name is not UNSET:
            field_dict["product_name"] = product_name
        if version_range is not UNSET:
            field_dict["version_range"] = version_range

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = CSAFProductStateStatus(d.pop("status"))

        def _parse_cpe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cpe = _parse_cpe(d.pop("cpe", UNSET))

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        model_numbers = cast(list[str], d.pop("model_numbers", UNSET))

        def _parse_product_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product_id = _parse_product_id(d.pop("product_id", UNSET))

        def _parse_product_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product_name = _parse_product_name(d.pop("product_name", UNSET))

        def _parse_version_range(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_range = _parse_version_range(d.pop("version_range", UNSET))

        csaf_product_state = cls(
            status=status,
            cpe=cpe,
            cve_id=cve_id,
            model_numbers=model_numbers,
            product_id=product_id,
            product_name=product_name,
            version_range=version_range,
        )

        csaf_product_state.additional_properties = d
        return csaf_product_state

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
