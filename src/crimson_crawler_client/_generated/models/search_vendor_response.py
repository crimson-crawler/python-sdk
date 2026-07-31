from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cpe_product import CPEProduct
    from ..models.error_detail import ErrorDetail


T = TypeVar("T", bound="SearchVendorResponse")


@_attrs_define
class SearchVendorResponse:
    """Vendor product listing with CPE identifiers.

    Attributes:
        vendor (str): Searched vendor name
        errors (list[ErrorDetail] | Unset): Partial failure details
        products (list[CPEProduct] | Unset): Products from the CPE dictionary
        total_products (int | Unset): Total number of products found Default: 0.
    """

    vendor: str
    errors: list[ErrorDetail] | Unset = UNSET
    products: list[CPEProduct] | Unset = UNSET
    total_products: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cpe_product import CPEProduct
        from ..models.error_detail import ErrorDetail

        vendor = self.vendor

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        products: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.products, Unset):
            products = []
            for products_item_data in self.products:
                products_item = products_item_data.to_dict()
                products.append(products_item)

        total_products = self.total_products

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor": vendor,
            }
        )
        if errors is not UNSET:
            field_dict["errors"] = errors
        if products is not UNSET:
            field_dict["products"] = products
        if total_products is not UNSET:
            field_dict["total_products"] = total_products

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cpe_product import CPEProduct
        from ..models.error_detail import ErrorDetail

        d = dict(src_dict)
        vendor = d.pop("vendor")

        _errors = d.pop("errors", UNSET)
        errors: list[ErrorDetail] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = ErrorDetail.from_dict(errors_item_data)

                errors.append(errors_item)

        _products = d.pop("products", UNSET)
        products: list[CPEProduct] | Unset = UNSET
        if _products is not UNSET:
            products = []
            for products_item_data in _products:
                products_item = CPEProduct.from_dict(products_item_data)

                products.append(products_item)

        total_products = d.pop("total_products", UNSET)

        search_vendor_response = cls(
            vendor=vendor,
            errors=errors,
            products=products,
            total_products=total_products,
        )

        search_vendor_response.additional_properties = d
        return search_vendor_response

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
