from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cpe_product import CPEProduct
    from ..models.cpe_vendor import CPEVendor
    from ..models.error_detail import ErrorDetail


T = TypeVar("T", bound="SearchVendorResponse")


@_attrs_define
class SearchVendorResponse:
    """Vendor product listing with CPE identifiers — or the vendor directory.

    Attributes:
        errors (list[ErrorDetail] | Unset): Partial failure details
        products (list[CPEProduct] | Unset): Products from the CPE dictionary (vendor mode). One row per CPE entry: a
            product with several versions contributes several rows, so this list is at least as long as the product count,
            not capped by `limit`.
        total_products (int | Unset): Number of distinct products represented in `products` (vendor mode) — version rows
            of the same product count once. Default: 0.
        total_vendors (int | Unset): Number of directory rows returned (directory mode) Default: 0.
        vendor (None | str | Unset): Vendor queried, or null in directory mode
        vendors (list[CPEVendor] | Unset): Vendor directory rows with product counts (directory mode — no `vendor`
            given)
    """

    errors: list[ErrorDetail] | Unset = UNSET
    products: list[CPEProduct] | Unset = UNSET
    total_products: int | Unset = 0
    total_vendors: int | Unset = 0
    vendor: None | str | Unset = UNSET
    vendors: list[CPEVendor] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.cpe_product import CPEProduct  # noqa: PLC0415
        from ..models.cpe_vendor import CPEVendor  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415

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

        total_vendors = self.total_vendors

        vendor: None | str | Unset
        if isinstance(self.vendor, Unset):
            vendor = UNSET
        else:
            vendor = self.vendor

        vendors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.vendors, Unset):
            vendors = []
            for vendors_item_data in self.vendors:
                vendors_item = vendors_item_data.to_dict()
                vendors.append(vendors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if errors is not UNSET:
            field_dict["errors"] = errors
        if products is not UNSET:
            field_dict["products"] = products
        if total_products is not UNSET:
            field_dict["total_products"] = total_products
        if total_vendors is not UNSET:
            field_dict["total_vendors"] = total_vendors
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if vendors is not UNSET:
            field_dict["vendors"] = vendors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cpe_product import CPEProduct  # noqa: PLC0415
        from ..models.cpe_vendor import CPEVendor  # noqa: PLC0415
        from ..models.error_detail import ErrorDetail  # noqa: PLC0415

        d = dict(src_dict)
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

        total_vendors = d.pop("total_vendors", UNSET)

        def _parse_vendor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor = _parse_vendor(d.pop("vendor", UNSET))

        _vendors = d.pop("vendors", UNSET)
        vendors: list[CPEVendor] | Unset = UNSET
        if _vendors is not UNSET:
            vendors = []
            for vendors_item_data in _vendors:
                vendors_item = CPEVendor.from_dict(vendors_item_data)

                vendors.append(vendors_item)

        search_vendor_response = cls(
            errors=errors,
            products=products,
            total_products=total_products,
            total_vendors=total_vendors,
            vendor=vendor,
            vendors=vendors,
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
