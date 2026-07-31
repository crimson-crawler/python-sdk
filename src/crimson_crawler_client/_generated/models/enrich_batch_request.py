from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.batch_atlas_item import BatchATLASItem
    from ..models.batch_campaign_item import BatchCampaignItem
    from ..models.batch_capec_item import BatchCAPECItem
    from ..models.batch_cve_item import BatchCVEItem
    from ..models.batch_cwe_item import BatchCWEItem
    from ..models.batch_d3fend_item import BatchD3FENDItem
    from ..models.batch_disarm_item import BatchDISARMItem
    from ..models.batch_group_item import BatchGroupItem
    from ..models.batch_ioc_item import BatchIOCItem
    from ..models.batch_location_item import BatchLocationItem
    from ..models.batch_package_item import BatchPackageItem
    from ..models.batch_po_c_source_item import BatchPoCSourceItem
    from ..models.batch_product_item import BatchProductItem
    from ..models.batch_sector_item import BatchSectorItem
    from ..models.batch_software_item import BatchSoftwareItem
    from ..models.batch_technique_item import BatchTechniqueItem


T = TypeVar("T", bound="EnrichBatchRequest")


@_attrs_define
class EnrichBatchRequest:
    """Batch-run up to 50 enrich/* lookups in one request.

    Each item carries a `type` discriminator naming one of the 16 enrich types
    plus that type's identifier fields and its own per-type `include` list. The
    51st item is rejected with HTTP 422 via the `max_length` constraint.

        Attributes:
            items (list[BatchATLASItem | BatchCampaignItem | BatchCAPECItem | BatchCVEItem | BatchCWEItem | BatchD3FENDItem
                | BatchDISARMItem | BatchGroupItem | BatchIOCItem | BatchLocationItem | BatchPackageItem | BatchPoCSourceItem |
                BatchProductItem | BatchSectorItem | BatchSoftwareItem | BatchTechniqueItem]): 1-50 enrichment items; the 51st
                is rejected with HTTP 422.
    """

    items: list[
        BatchATLASItem
        | BatchCampaignItem
        | BatchCAPECItem
        | BatchCVEItem
        | BatchCWEItem
        | BatchD3FENDItem
        | BatchDISARMItem
        | BatchGroupItem
        | BatchIOCItem
        | BatchLocationItem
        | BatchPackageItem
        | BatchPoCSourceItem
        | BatchProductItem
        | BatchSectorItem
        | BatchSoftwareItem
        | BatchTechniqueItem
    ]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.batch_atlas_item import BatchATLASItem
        from ..models.batch_campaign_item import BatchCampaignItem
        from ..models.batch_capec_item import BatchCAPECItem
        from ..models.batch_cve_item import BatchCVEItem
        from ..models.batch_cwe_item import BatchCWEItem
        from ..models.batch_d3fend_item import BatchD3FENDItem
        from ..models.batch_disarm_item import BatchDISARMItem
        from ..models.batch_group_item import BatchGroupItem
        from ..models.batch_ioc_item import BatchIOCItem
        from ..models.batch_location_item import BatchLocationItem
        from ..models.batch_package_item import BatchPackageItem
        from ..models.batch_po_c_source_item import BatchPoCSourceItem
        from ..models.batch_product_item import BatchProductItem
        from ..models.batch_sector_item import BatchSectorItem
        from ..models.batch_software_item import BatchSoftwareItem
        from ..models.batch_technique_item import BatchTechniqueItem

        items = []
        for items_item_data in self.items:
            items_item: dict[str, Any]
            if isinstance(items_item_data, BatchCVEItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchProductItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchPackageItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchCWEItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchCAPECItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchTechniqueItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchIOCItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchGroupItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchSoftwareItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchCampaignItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchATLASItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchDISARMItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchLocationItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchSectorItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchD3FENDItem):
                items_item = items_item_data.to_dict()
            else:
                items_item = items_item_data.to_dict()

            items.append(items_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "items": items,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.batch_atlas_item import BatchATLASItem
        from ..models.batch_campaign_item import BatchCampaignItem
        from ..models.batch_capec_item import BatchCAPECItem
        from ..models.batch_cve_item import BatchCVEItem
        from ..models.batch_cwe_item import BatchCWEItem
        from ..models.batch_d3fend_item import BatchD3FENDItem
        from ..models.batch_disarm_item import BatchDISARMItem
        from ..models.batch_group_item import BatchGroupItem
        from ..models.batch_ioc_item import BatchIOCItem
        from ..models.batch_location_item import BatchLocationItem
        from ..models.batch_package_item import BatchPackageItem
        from ..models.batch_po_c_source_item import BatchPoCSourceItem
        from ..models.batch_product_item import BatchProductItem
        from ..models.batch_sector_item import BatchSectorItem
        from ..models.batch_software_item import BatchSoftwareItem
        from ..models.batch_technique_item import BatchTechniqueItem

        d = dict(src_dict)
        items = []
        _items = d.pop("items")
        for items_item_data in _items:

            def _parse_items_item(
                data: object,
            ) -> (
                BatchATLASItem
                | BatchCampaignItem
                | BatchCAPECItem
                | BatchCVEItem
                | BatchCWEItem
                | BatchD3FENDItem
                | BatchDISARMItem
                | BatchGroupItem
                | BatchIOCItem
                | BatchLocationItem
                | BatchPackageItem
                | BatchPoCSourceItem
                | BatchProductItem
                | BatchSectorItem
                | BatchSoftwareItem
                | BatchTechniqueItem
            ):
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0 = BatchCVEItem.from_dict(data)

                    return items_item_type_0
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_1 = BatchProductItem.from_dict(data)

                    return items_item_type_1
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_2 = BatchPackageItem.from_dict(data)

                    return items_item_type_2
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_3 = BatchCWEItem.from_dict(data)

                    return items_item_type_3
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_4 = BatchCAPECItem.from_dict(data)

                    return items_item_type_4
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_5 = BatchTechniqueItem.from_dict(data)

                    return items_item_type_5
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_6 = BatchIOCItem.from_dict(data)

                    return items_item_type_6
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_7 = BatchGroupItem.from_dict(data)

                    return items_item_type_7
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_8 = BatchSoftwareItem.from_dict(data)

                    return items_item_type_8
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_9 = BatchCampaignItem.from_dict(data)

                    return items_item_type_9
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_10 = BatchATLASItem.from_dict(data)

                    return items_item_type_10
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_11 = BatchDISARMItem.from_dict(data)

                    return items_item_type_11
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_12 = BatchLocationItem.from_dict(data)

                    return items_item_type_12
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_13 = BatchSectorItem.from_dict(data)

                    return items_item_type_13
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_14 = BatchD3FENDItem.from_dict(data)

                    return items_item_type_14
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                if not isinstance(data, dict):
                    raise TypeError()
                items_item_type_15 = BatchPoCSourceItem.from_dict(data)

                return items_item_type_15

            items_item = _parse_items_item(items_item_data)

            items.append(items_item)

        enrich_batch_request = cls(
            items=items,
        )

        enrich_batch_request.additional_properties = d
        return enrich_batch_request

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
