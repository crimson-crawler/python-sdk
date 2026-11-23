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
    from ..models.batch_cloak_item import BatchCloakItem
    from ..models.batch_cve_item import BatchCVEItem
    from ..models.batch_cwe_item import BatchCWEItem
    from ..models.batch_d3fend_item import BatchD3FENDItem
    from ..models.batch_disarm_item import BatchDISARMItem
    from ..models.batch_f3_item import BatchF3Item
    from ..models.batch_group_item import BatchGroupItem
    from ..models.batch_ioc_item import BatchIOCItem
    from ..models.batch_location_item import BatchLocationItem
    from ..models.batch_package_item import BatchPackageItem
    from ..models.batch_po_c_source_item import BatchPoCSourceItem
    from ..models.batch_product_item import BatchProductItem
    from ..models.batch_sector_item import BatchSectorItem
    from ..models.batch_software_item import BatchSoftwareItem
    from ..models.batch_technique_item import BatchTechniqueItem
    from ..models.invalid_batch_item import InvalidBatchItem


T = TypeVar("T", bound="EnrichBatchRequest")


@_attrs_define
class EnrichBatchRequest:
    """Batch-run up to 50 enrich/* lookups in one request.

    Each item carries a `type` discriminator naming one of the 18 enrich types
    plus that type's identifier fields and its own per-type `include` list. The
    51st item is rejected with HTTP 422 via the `max_length` constraint.

    An item that no type accepts (unknown discriminator, or a missing/invalid required field for a
    known one) is NOT a request-level error: it comes back as its own `status="error"` result so the
    batch's other items still run.

        Attributes:
            items (list[BatchATLASItem | BatchCampaignItem | BatchCAPECItem | BatchCloakItem | BatchCVEItem | BatchCWEItem |
                BatchD3FENDItem | BatchDISARMItem | BatchF3Item | BatchGroupItem | BatchIOCItem | BatchLocationItem |
                BatchPackageItem | BatchPoCSourceItem | BatchProductItem | BatchSectorItem | BatchSoftwareItem |
                BatchTechniqueItem | InvalidBatchItem]): 1-50 enrichment items; the 51st is rejected with HTTP 422. An item no
                supported type accepts is reported as a per-item `status='error'` result in `results[]` rather than failing the
                request.
    """

    items: list[
        BatchATLASItem
        | BatchCampaignItem
        | BatchCAPECItem
        | BatchCloakItem
        | BatchCVEItem
        | BatchCWEItem
        | BatchD3FENDItem
        | BatchDISARMItem
        | BatchF3Item
        | BatchGroupItem
        | BatchIOCItem
        | BatchLocationItem
        | BatchPackageItem
        | BatchPoCSourceItem
        | BatchProductItem
        | BatchSectorItem
        | BatchSoftwareItem
        | BatchTechniqueItem
        | InvalidBatchItem
    ]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.batch_atlas_item import BatchATLASItem  # noqa: PLC0415
        from ..models.batch_campaign_item import BatchCampaignItem  # noqa: PLC0415
        from ..models.batch_capec_item import BatchCAPECItem  # noqa: PLC0415
        from ..models.batch_cloak_item import BatchCloakItem  # noqa: PLC0415
        from ..models.batch_cve_item import BatchCVEItem  # noqa: PLC0415
        from ..models.batch_cwe_item import BatchCWEItem  # noqa: PLC0415
        from ..models.batch_d3fend_item import BatchD3FENDItem  # noqa: PLC0415
        from ..models.batch_disarm_item import BatchDISARMItem  # noqa: PLC0415
        from ..models.batch_f3_item import BatchF3Item  # noqa: PLC0415
        from ..models.batch_group_item import BatchGroupItem  # noqa: PLC0415
        from ..models.batch_ioc_item import BatchIOCItem  # noqa: PLC0415
        from ..models.batch_location_item import BatchLocationItem  # noqa: PLC0415
        from ..models.batch_package_item import BatchPackageItem  # noqa: PLC0415
        from ..models.batch_po_c_source_item import BatchPoCSourceItem  # noqa: PLC0415
        from ..models.batch_product_item import BatchProductItem  # noqa: PLC0415
        from ..models.batch_sector_item import BatchSectorItem  # noqa: PLC0415
        from ..models.batch_software_item import BatchSoftwareItem  # noqa: PLC0415
        from ..models.batch_technique_item import BatchTechniqueItem  # noqa: PLC0415
        from ..models.invalid_batch_item import InvalidBatchItem  # noqa: PLC0415

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
            elif isinstance(items_item_data, BatchF3Item):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchCloakItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchLocationItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchSectorItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchD3FENDItem):
                items_item = items_item_data.to_dict()
            elif isinstance(items_item_data, BatchPoCSourceItem):
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
        from ..models.batch_atlas_item import BatchATLASItem  # noqa: PLC0415
        from ..models.batch_campaign_item import BatchCampaignItem  # noqa: PLC0415
        from ..models.batch_capec_item import BatchCAPECItem  # noqa: PLC0415
        from ..models.batch_cloak_item import BatchCloakItem  # noqa: PLC0415
        from ..models.batch_cve_item import BatchCVEItem  # noqa: PLC0415
        from ..models.batch_cwe_item import BatchCWEItem  # noqa: PLC0415
        from ..models.batch_d3fend_item import BatchD3FENDItem  # noqa: PLC0415
        from ..models.batch_disarm_item import BatchDISARMItem  # noqa: PLC0415
        from ..models.batch_f3_item import BatchF3Item  # noqa: PLC0415
        from ..models.batch_group_item import BatchGroupItem  # noqa: PLC0415
        from ..models.batch_ioc_item import BatchIOCItem  # noqa: PLC0415
        from ..models.batch_location_item import BatchLocationItem  # noqa: PLC0415
        from ..models.batch_package_item import BatchPackageItem  # noqa: PLC0415
        from ..models.batch_po_c_source_item import BatchPoCSourceItem  # noqa: PLC0415
        from ..models.batch_product_item import BatchProductItem  # noqa: PLC0415
        from ..models.batch_sector_item import BatchSectorItem  # noqa: PLC0415
        from ..models.batch_software_item import BatchSoftwareItem  # noqa: PLC0415
        from ..models.batch_technique_item import BatchTechniqueItem  # noqa: PLC0415
        from ..models.invalid_batch_item import InvalidBatchItem  # noqa: PLC0415

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
                | BatchCloakItem
                | BatchCVEItem
                | BatchCWEItem
                | BatchD3FENDItem
                | BatchDISARMItem
                | BatchF3Item
                | BatchGroupItem
                | BatchIOCItem
                | BatchLocationItem
                | BatchPackageItem
                | BatchPoCSourceItem
                | BatchProductItem
                | BatchSectorItem
                | BatchSoftwareItem
                | BatchTechniqueItem
                | InvalidBatchItem
            ):
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_0 = BatchCVEItem.from_dict(data)

                    return items_item_type_0_type_0
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_1 = BatchProductItem.from_dict(data)

                    return items_item_type_0_type_1
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_2 = BatchPackageItem.from_dict(data)

                    return items_item_type_0_type_2
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_3 = BatchCWEItem.from_dict(data)

                    return items_item_type_0_type_3
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_4 = BatchCAPECItem.from_dict(data)

                    return items_item_type_0_type_4
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_5 = BatchTechniqueItem.from_dict(data)

                    return items_item_type_0_type_5
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_6 = BatchIOCItem.from_dict(data)

                    return items_item_type_0_type_6
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_7 = BatchGroupItem.from_dict(data)

                    return items_item_type_0_type_7
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_8 = BatchSoftwareItem.from_dict(data)

                    return items_item_type_0_type_8
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_9 = BatchCampaignItem.from_dict(data)

                    return items_item_type_0_type_9
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_10 = BatchATLASItem.from_dict(data)

                    return items_item_type_0_type_10
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_11 = BatchDISARMItem.from_dict(data)

                    return items_item_type_0_type_11
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_12 = BatchF3Item.from_dict(data)

                    return items_item_type_0_type_12
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_13 = BatchCloakItem.from_dict(data)

                    return items_item_type_0_type_13
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_14 = BatchLocationItem.from_dict(data)

                    return items_item_type_0_type_14
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_15 = BatchSectorItem.from_dict(data)

                    return items_item_type_0_type_15
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_16 = BatchD3FENDItem.from_dict(data)

                    return items_item_type_0_type_16
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError()
                    items_item_type_0_type_17 = BatchPoCSourceItem.from_dict(data)

                    return items_item_type_0_type_17
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                if not isinstance(data, dict):
                    raise TypeError()
                items_item_type_1 = InvalidBatchItem.from_dict(data)

                return items_item_type_1

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
