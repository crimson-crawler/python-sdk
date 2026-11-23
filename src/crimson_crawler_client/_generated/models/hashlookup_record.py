from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.hashlookup_record_hash_type import HashlookupRecordHashType
from ..models.hashlookup_record_status import HashlookupRecordStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="HashlookupRecord")


@_attrs_define
class HashlookupRecord:
    """A CIRCL hashlookup verdict for one file hash.

    The wrapper always exists when the token is requested for a hash indicator: a 404 is
    an answer (`known=false`, `status="ok"`), while a read failure keeps the wrapper with
    `status="unavailable"` and an `errors[]` entry beside it.

        Attributes:
            hash_ (str): The hash that was looked up
            hash_type (HashlookupRecordHashType): Hash algorithm
            known (bool): Whether hashlookup knows this hash
            source_url (str): The hashlookup API URL this record was read from
            status (HashlookupRecordStatus): ok | unavailable | auth_required | terms_not_accepted
            error (None | str | Unset): Sanitized failure reason (unavailable rows only)
            nsrl (bool | None | Unset): Whether the hash is in the NSRL known-good set
            package (None | str | Unset): Package/file name the record carries
            product (None | str | Unset): Product the known file belongs to
            retrieved_at (str | Unset): When this codebase read it (ISO 8601) Default: ''.
            source (str | Unset): Stable source label Default: 'hashlookup'.
            trust (int | None | Unset): CIRCL's trust score for the record (`hashlookup:trust`)
    """

    hash_: str
    hash_type: HashlookupRecordHashType
    known: bool
    source_url: str
    status: HashlookupRecordStatus
    error: None | str | Unset = UNSET
    nsrl: bool | None | Unset = UNSET
    package: None | str | Unset = UNSET
    product: None | str | Unset = UNSET
    retrieved_at: str | Unset = ""
    source: str | Unset = "hashlookup"
    trust: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hash_ = self.hash_

        hash_type = self.hash_type.value

        known = self.known

        source_url = self.source_url

        status = self.status.value

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        nsrl: bool | None | Unset
        if isinstance(self.nsrl, Unset):
            nsrl = UNSET
        else:
            nsrl = self.nsrl

        package: None | str | Unset
        if isinstance(self.package, Unset):
            package = UNSET
        else:
            package = self.package

        product: None | str | Unset
        if isinstance(self.product, Unset):
            product = UNSET
        else:
            product = self.product

        retrieved_at = self.retrieved_at

        source = self.source

        trust: int | None | Unset
        if isinstance(self.trust, Unset):
            trust = UNSET
        else:
            trust = self.trust

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hash": hash_,
                "hash_type": hash_type,
                "known": known,
                "source_url": source_url,
                "status": status,
            }
        )
        if error is not UNSET:
            field_dict["error"] = error
        if nsrl is not UNSET:
            field_dict["nsrl"] = nsrl
        if package is not UNSET:
            field_dict["package"] = package
        if product is not UNSET:
            field_dict["product"] = product
        if retrieved_at is not UNSET:
            field_dict["retrieved_at"] = retrieved_at
        if source is not UNSET:
            field_dict["source"] = source
        if trust is not UNSET:
            field_dict["trust"] = trust

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        hash_ = d.pop("hash")

        hash_type = HashlookupRecordHashType(d.pop("hash_type"))

        known = d.pop("known")

        source_url = d.pop("source_url")

        status = HashlookupRecordStatus(d.pop("status"))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        def _parse_nsrl(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        nsrl = _parse_nsrl(d.pop("nsrl", UNSET))

        def _parse_package(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        package = _parse_package(d.pop("package", UNSET))

        def _parse_product(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        product = _parse_product(d.pop("product", UNSET))

        retrieved_at = d.pop("retrieved_at", UNSET)

        source = d.pop("source", UNSET)

        def _parse_trust(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        trust = _parse_trust(d.pop("trust", UNSET))

        hashlookup_record = cls(
            hash_=hash_,
            hash_type=hash_type,
            known=known,
            source_url=source_url,
            status=status,
            error=error,
            nsrl=nsrl,
            package=package,
            product=product,
            retrieved_at=retrieved_at,
            source=source,
            trust=trust,
        )

        hashlookup_record.additional_properties = d
        return hashlookup_record

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
