from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DomainContext")


@_attrs_define
class DomainContext:
    """Domain registration facts from RDAP (IANA-bootstrapped registry).

    Attributes:
        domain (str): The registrable domain that was looked up
        source (str): The registry that answered (its RDAP hostname, from IANA's bootstrap). Only registries cleared for
            per-query use by the operator are queried.
        age_days (int | None | Unset): Whole days between registration and now; null when unregistered
        expiration_date (None | str | Unset): Registry expiration event (ISO-8601, UTC)
        registrar (None | str | Unset): Registrar name from the registry's RDAP entity
        registration_date (None | str | Unset): Registry registration event (ISO-8601, UTC)
        status (list[str] | Unset): RDAP status codes exactly as the registry publishes them
    """

    domain: str
    source: str
    age_days: int | None | Unset = UNSET
    expiration_date: None | str | Unset = UNSET
    registrar: None | str | Unset = UNSET
    registration_date: None | str | Unset = UNSET
    status: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        source = self.source

        age_days: int | None | Unset
        if isinstance(self.age_days, Unset):
            age_days = UNSET
        else:
            age_days = self.age_days

        expiration_date: None | str | Unset
        if isinstance(self.expiration_date, Unset):
            expiration_date = UNSET
        else:
            expiration_date = self.expiration_date

        registrar: None | str | Unset
        if isinstance(self.registrar, Unset):
            registrar = UNSET
        else:
            registrar = self.registrar

        registration_date: None | str | Unset
        if isinstance(self.registration_date, Unset):
            registration_date = UNSET
        else:
            registration_date = self.registration_date

        status: list[str] | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain": domain,
                "source": source,
            }
        )
        if age_days is not UNSET:
            field_dict["age_days"] = age_days
        if expiration_date is not UNSET:
            field_dict["expiration_date"] = expiration_date
        if registrar is not UNSET:
            field_dict["registrar"] = registrar
        if registration_date is not UNSET:
            field_dict["registration_date"] = registration_date
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        source = d.pop("source")

        def _parse_age_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        age_days = _parse_age_days(d.pop("age_days", UNSET))

        def _parse_expiration_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expiration_date = _parse_expiration_date(d.pop("expiration_date", UNSET))

        def _parse_registrar(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        registrar = _parse_registrar(d.pop("registrar", UNSET))

        def _parse_registration_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        registration_date = _parse_registration_date(d.pop("registration_date", UNSET))

        status = cast(list[str], d.pop("status", UNSET))

        domain_context = cls(
            domain=domain,
            source=source,
            age_days=age_days,
            expiration_date=expiration_date,
            registrar=registrar,
            registration_date=registration_date,
            status=status,
        )

        domain_context.additional_properties = d
        return domain_context

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
